use super::*;

#[test]
fn packet_device_view_v1_exposes_contract_and_device_generation() {
    let view = packet_device_object_view_v1(&PacketDeviceObjectManifest {
        id: 51,
        name: "net0".to_owned(),
        device: 17,
        device_generation: 2,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 60,
        note: "packet device".to_owned(),
    });
    assert_eq!(view["kind"], "packet-device");
    assert_eq!(view["owner"]["device"]["kind"], "device");
    assert_eq!(view["owner"]["device"]["generation"], 2);
    assert_eq!(view["contract"]["mtu"], 1500);
    assert_eq!(view["contract"]["rx_queue_depth"], 4);
    assert_eq!(view["contract"]["max_payload_len"], 512);
    assert_eq!(view["identity"]["mac"][5], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 60);
}

#[test]
fn packet_buffer_view_v1_exposes_contract_and_packet_device_generation() {
    let view = packet_buffer_object_view_v1(&PacketBufferObjectManifest {
        id: 52,
        packet_device: 51,
        packet_device_generation: 3,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 9,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 61,
        note: "packet buffer".to_owned(),
    });
    assert_eq!(view["kind"], "packet-buffer");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 3);
    assert_eq!(view["contract"]["direction"], "rx");
    assert_eq!(view["contract"]["capacity"], 512);
    assert_eq!(view["contract"]["payload_len"], 64);
    assert_eq!(view["contract"]["sequence"], 9);
    assert_eq!(view["last_transition"]["recorded_at_event"], 61);
}

#[test]
fn packet_queue_view_v1_exposes_role_depth_and_packet_device_generation() {
    let view = packet_queue_object_view_v1(&PacketQueueObjectManifest {
        id: 53,
        name: "net0-rx0".to_owned(),
        packet_device: 51,
        packet_device_generation: 3,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 62,
        note: "packet queue".to_owned(),
    });
    assert_eq!(view["kind"], "packet-queue");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 3);
    assert_eq!(view["identity"]["name"], "net0-rx0");
    assert_eq!(view["identity"]["role"], "rx");
    assert_eq!(view["identity"]["queue_index"], 0);
    assert_eq!(view["contract"]["depth"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 62);
}

#[test]
fn packet_descriptor_view_v1_exposes_queue_buffer_and_length() {
    let view = packet_descriptor_object_view_v1(&PacketDescriptorObjectManifest {
        id: 54,
        packet_queue: 53,
        packet_queue_generation: 2,
        packet_buffer: 52,
        packet_buffer_generation: 3,
        slot: 1,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 63,
        note: "packet descriptor".to_owned(),
    });
    assert_eq!(view["kind"], "packet-descriptor");
    assert_eq!(view["owner"]["packet_queue"]["kind"], "packet-queue");
    assert_eq!(view["owner"]["packet_queue"]["generation"], 2);
    assert_eq!(view["owner"]["packet_buffer"]["kind"], "packet-buffer");
    assert_eq!(view["owner"]["packet_buffer"]["generation"], 3);
    assert_eq!(view["identity"]["slot"], 1);
    assert_eq!(view["contract"]["length"], 64);
    assert_eq!(view["last_transition"]["recorded_at_event"], 63);
}

#[test]
fn fake_net_backend_view_v1_exposes_packet_device_and_profile_contract() {
    let view = fake_net_backend_object_view_v1(&FakeNetBackendObjectManifest {
        id: 55,
        name: "fake-net0".to_owned(),
        packet_device: 51,
        packet_device_generation: 4,
        provider: "service_core".to_owned(),
        profile: "fake-net-v1".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        deterministic_seed: 7,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 64,
        note: "fake backend".to_owned(),
    });
    assert_eq!(view["kind"], "fake-net-backend");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["identity"]["provider"], "service_core");
    assert_eq!(view["identity"]["profile"], "fake-net-v1");
    assert_eq!(view["contract"]["mtu"], 1500);
    assert_eq!(view["contract"]["mac"][5], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 64);
}

#[test]
fn virtio_net_backend_view_v1_exposes_driver_binding_and_profile_contract() {
    let view = virtio_net_backend_object_view_v1(&VirtioNetBackendObjectManifest {
        id: 56,
        name: "virtio-net0-backend".to_owned(),
        packet_device: 51,
        packet_device_generation: 4,
        driver_binding: 57,
        driver_binding_generation: 2,
        device: 50,
        device_generation: 4,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-net-backend-skeleton-v1".to_owned(),
        model: "virtio-net".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        device_features: 32,
        driver_features: 32,
        negotiated_features: 32,
        rx_queue_index: 0,
        tx_queue_index: 1,
        queue_size: 4,
        irq_vector: 5,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 65,
        note: "virtio backend".to_owned(),
    });
    assert_eq!(view["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["driver_binding"]["kind"], "driver-store-binding");
    assert_eq!(view["owner"]["driver_binding"]["generation"], 2);
    assert_eq!(view["identity"]["provider"], "substrate_virtio");
    assert_eq!(view["identity"]["profile"], "virtio-net-backend-skeleton-v1");
    assert_eq!(view["contract"]["negotiated_features"], 32);
    assert_eq!(view["contract"]["queue_size"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 65);
}

#[test]
fn network_rx_interrupt_view_v1_exposes_irq_and_rx_queue_generations() {
    let view = network_rx_interrupt_view_v1(&NetworkRxInterruptManifest {
        id: 58,
        virtio_net_backend: 56,
        virtio_net_backend_generation: 1,
        irq_event: 59,
        irq_event_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        rx_queue: 53,
        rx_queue_generation: 3,
        ready_descriptors: 1,
        sequence: 9,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 66,
        note: "rx interrupt".to_owned(),
    });
    assert_eq!(view["kind"], "network-rx-interrupt");
    assert_eq!(view["owner"]["virtio_net_backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["references"]["irq_event"]["kind"], "irq-event");
    assert_eq!(view["references"]["irq_event"]["generation"], 2);
    assert_eq!(view["references"]["rx_queue"]["generation"], 3);
    assert_eq!(view["readiness"]["ready_descriptors"], 1);
    assert_eq!(view["readiness"]["sequence"], 9);
    assert_eq!(view["last_transition"]["recorded_at_event"], 66);
}

#[test]
fn network_rx_wait_resolution_view_v1_exposes_wait_and_interrupt_generations() {
    let view = network_rx_wait_resolution_view_v1(&NetworkRxWaitResolutionManifest {
        id: 60,
        io_wait: 61,
        io_wait_generation: 2,
        wait: 62,
        wait_generation: 3,
        rx_interrupt: 58,
        rx_interrupt_generation: 1,
        irq_event: 59,
        irq_event_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        rx_queue: 53,
        rx_queue_generation: 3,
        ready_descriptors: 1,
        sequence: 9,
        generation: 1,
        state: "resolved".to_owned(),
        resolved_at_event: 67,
        note: "rx wait resolution".to_owned(),
    });
    assert_eq!(view["kind"], "network-rx-wait-resolution");
    assert_eq!(view["owner"]["io_wait"]["kind"], "io-wait");
    assert_eq!(view["owner"]["io_wait"]["generation"], 2);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["wait"]["generation"], 3);
    assert_eq!(view["references"]["rx_interrupt"]["kind"], "network-rx-interrupt");
    assert_eq!(view["references"]["rx_queue"]["generation"], 3);
    assert_eq!(view["readiness"]["sequence"], 9);
    assert_eq!(view["last_transition"]["resolved_at_event"], 67);
}

#[test]
fn network_tx_capability_gate_view_v1_exposes_capability_and_descriptor_generations() {
    let view = network_tx_capability_gate_view_v1(&NetworkTxCapabilityGateManifest {
        id: 68,
        driver_store: 7,
        driver_store_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        tx_queue: 53,
        tx_queue_generation: 3,
        packet_descriptor: 54,
        packet_descriptor_generation: 2,
        packet_buffer: 52,
        packet_buffer_generation: 3,
        device_capability: 69,
        device_capability_generation: 1,
        capability: 70,
        capability_generation: 5,
        handle_slot: 4,
        handle_generation: 5,
        handle_tag: 99,
        operation: "tx".to_owned(),
        byte_len: 64,
        sequence: 9,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 68,
        note: "tx gate".to_owned(),
    });
    assert_eq!(view["kind"], "network-tx-capability-gate");
    assert_eq!(view["owner"]["driver_store"]["kind"], "store");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["references"]["packet_descriptor"]["kind"], "packet-descriptor");
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 2);
    assert_eq!(view["references"]["device_capability"]["kind"], "device-capability");
    assert_eq!(view["references"]["capability"]["generation"], 5);
    assert_eq!(view["authority"]["operation"], "tx");
    assert_eq!(view["authority"]["handle_slot"], 4);
    assert_eq!(view["tx"]["byte_len"], 64);
    assert_eq!(view["last_transition"]["recorded_at_event"], 68);
}

#[test]
fn network_tx_completion_view_v1_exposes_gate_backend_and_descriptor_generations() {
    let view = network_tx_completion_view_v1(&NetworkTxCompletionManifest {
        id: 71,
        tx_gate: 68,
        tx_gate_generation: 2,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 72,
        backend_generation: 3,
        driver_store: 7,
        driver_store_generation: 4,
        packet_device: 51,
        packet_device_generation: 5,
        tx_queue: 53,
        tx_queue_generation: 6,
        packet_descriptor: 54,
        packet_descriptor_generation: 7,
        packet_buffer: 52,
        packet_buffer_generation: 8,
        byte_len: 64,
        sequence: 9,
        completion_sequence: 10,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 73,
        note: "tx completion".to_owned(),
    });
    assert_eq!(view["kind"], "network-tx-completion");
    assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["backend"]["generation"], 3);
    assert_eq!(view["references"]["tx_gate"]["kind"], "network-tx-capability-gate");
    assert_eq!(view["references"]["tx_gate"]["generation"], 2);
    assert_eq!(view["references"]["packet_descriptor"]["kind"], "packet-descriptor");
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 7);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 8);
    assert_eq!(view["tx"]["completion_sequence"], 10);
    assert_eq!(view["last_transition"]["completed_at_event"], 73);
}

#[test]
fn network_stack_adapter_view_v1_exposes_smoltcp_profile_and_queue_generations() {
    let view = network_stack_adapter_view_v1(&NetworkStackAdapterManifest {
        id: 74,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 72,
        backend_generation: 3,
        packet_device: 51,
        packet_device_generation: 5,
        rx_queue: 53,
        rx_queue_generation: 6,
        tx_queue: 54,
        tx_queue_generation: 7,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        ipv4_addr: [10, 0, 2, 15],
        ipv4_prefix_len: 24,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        max_payload_len: 512,
        socket_capacity: 0,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 75,
        note: "smoltcp adapter".to_owned(),
    });
    assert_eq!(view["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["backend"]["kind"], "virtio-net-backend");
    assert_eq!(view["owner"]["backend"]["generation"], 3);
    assert_eq!(view["references"]["packet_device"]["generation"], 5);
    assert_eq!(view["references"]["rx_queue"]["generation"], 6);
    assert_eq!(view["references"]["tx_queue"]["generation"], 7);
    assert_eq!(view["adapter"]["implementation"], "smoltcp");
    assert_eq!(view["adapter"]["socket_capacity"], 0);
    assert_eq!(view["network"]["ipv4_prefix_len"], 24);
    assert_eq!(view["last_transition"]["recorded_at_event"], 75);
}

#[test]
fn socket_object_view_v1_exposes_adapter_store_and_socket_contract() {
    let view = socket_object_view_v1(&SocketObjectManifest {
        id: 76,
        adapter: 74,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 77,
        note: "socket object".to_owned(),
    });
    assert_eq!(view["kind"], "socket-object");
    assert_eq!(view["owner"]["store"]["kind"], "store");
    assert_eq!(view["owner"]["store"]["generation"], 3);
    assert_eq!(view["references"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["references"]["adapter"]["generation"], 1);
    assert_eq!(view["socket"]["domain"], 2);
    assert_eq!(view["socket"]["type"], 1);
    assert_eq!(view["socket"]["canonical_protocol"], 6);
    assert_eq!(view["socket"]["family"], "inet");
    assert_eq!(view["socket"]["transport"], "tcp");
    assert_eq!(view["last_transition"]["created_at_event"], 77);
}

#[test]
fn endpoint_object_view_v1_exposes_socket_store_and_endpoint_contract() {
    let view = endpoint_object_view_v1(&EndpointObjectManifest {
        id: 78,
        socket: 76,
        socket_generation: 1,
        adapter: 74,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 79,
        note: "endpoint object".to_owned(),
    });
    assert_eq!(view["kind"], "endpoint-object");
    assert_eq!(view["owner"]["store"]["kind"], "store");
    assert_eq!(view["owner"]["store"]["generation"], 3);
    assert_eq!(view["owner"]["socket"]["kind"], "socket-object");
    assert_eq!(view["references"]["socket"]["generation"], 1);
    assert_eq!(view["references"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["endpoint"]["family"], "inet");
    assert_eq!(view["endpoint"]["transport"], "tcp");
    assert_eq!(view["endpoint"]["local_port"], 0);
    assert_eq!(view["endpoint"]["remote_port"], 0);
    assert_eq!(view["last_transition"]["created_at_event"], 79);
}

#[test]
fn socket_operation_view_v1_exposes_endpoint_operation_and_generations() {
    let view = socket_operation_view_v1(&SocketOperationManifest {
        id: 80,
        endpoint: 78,
        endpoint_generation: 1,
        socket: 76,
        socket_generation: 2,
        adapter: 74,
        adapter_generation: 3,
        owner_store: 7,
        owner_store_generation: 4,
        operation: "connect".to_owned(),
        local_addr: [10, 0, 2, 15],
        local_port: 40000,
        remote_addr: [10, 0, 2, 2],
        remote_port: 80,
        backlog: 0,
        byte_len: 0,
        sequence: 2,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 81,
        note: "socket operation".to_owned(),
    });
    assert_eq!(view["kind"], "socket-operation");
    assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["owner"]["endpoint"]["generation"], 1);
    assert_eq!(view["references"]["socket"]["kind"], "socket-object");
    assert_eq!(view["references"]["socket"]["generation"], 2);
    assert_eq!(view["references"]["adapter"]["generation"], 3);
    assert_eq!(view["references"]["owner_store"]["generation"], 4);
    assert_eq!(view["operation"]["name"], "connect");
    assert_eq!(view["operation"]["sequence"], 2);
    assert_eq!(view["operation"]["local_port"], 40000);
    assert_eq!(view["operation"]["remote_port"], 80);
    assert_eq!(view["last_transition"]["recorded_at_event"], 81);
}

#[test]
fn socket_wait_view_v1_exposes_wait_endpoint_and_readiness_generations() {
    let view = socket_wait_view_v1(&SocketWaitManifest {
        id: 82,
        wait: 900,
        wait_generation: 2,
        endpoint: 78,
        endpoint_generation: 3,
        socket: 76,
        socket_generation: 4,
        adapter: 74,
        adapter_generation: 5,
        owner_store: 7,
        owner_store_generation: 6,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 78,
            generation: 3,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 83,
        completed_at_event: Some(84),
        cancel_reason: None,
        ready_sequence: Some(9),
        byte_len: Some(19),
        note: "socket wait".to_owned(),
    });
    assert_eq!(view["kind"], "socket-wait");
    assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
    assert_eq!(view["owner"]["wait"]["generation"], 2);
    assert_eq!(view["owner"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["owner"]["endpoint"]["generation"], 3);
    assert_eq!(view["references"]["socket"]["generation"], 4);
    assert_eq!(view["references"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["owner_store"]["generation"], 6);
    assert_eq!(view["references"]["blocker"]["kind"], "endpoint-object");
    assert_eq!(view["wait"]["kind"], "socket-readable");
    assert_eq!(view["wait"]["ready_sequence"], 9);
    assert_eq!(view["wait"]["byte_len"], 19);
    assert_eq!(view["last_transition"]["completed_at_event"], 84);
}

#[test]
fn network_backpressure_view_v1_exposes_policy_refs_and_drops() {
    let view = network_backpressure_view_v1(&NetworkBackpressureManifest {
        id: 85,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 6,
        packet_queue: 53,
        packet_queue_generation: 7,
        endpoint: Some(76),
        endpoint_generation: Some(8),
        socket: Some(75),
        socket_generation: Some(9),
        owner_store: Some(7),
        owner_store_generation: Some(10),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 11,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 86,
        note: "backpressure".to_owned(),
    });
    assert_eq!(view["kind"], "network-backpressure");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["packet_queue"]["generation"], 7);
    assert_eq!(view["references"]["endpoint"]["kind"], "endpoint-object");
    assert_eq!(view["references"]["socket"]["generation"], 9);
    assert_eq!(view["references"]["owner_store"]["generation"], 10);
    assert_eq!(view["policy"]["direction"], "tx");
    assert_eq!(view["policy"]["reason"], "queue-full");
    assert_eq!(view["policy"]["action"], "reject-send");
    assert_eq!(view["policy"]["queue_depth"], 4);
    assert_eq!(view["policy"]["dropped_packets"], 0);
    assert_eq!(view["last_transition"]["recorded_at_event"], 86);
}

#[test]
fn network_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = network_driver_cleanup_view_v1(&NetworkDriverCleanupManifest {
        id: 87,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 2,
        packet_device: 51,
        packet_device_generation: 4,
        adapter: 74,
        adapter_generation: 5,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 6,
        },
        cancelled_socket_waits: vec![ContractObjectRefManifest {
            kind: "socket-wait".to_owned(),
            id: 90,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 91,
            generation: 1,
        }],
        revoked_packet_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 92,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 88,
        completed_at_event: Some(89),
        reason: "device-fault".to_owned(),
        note: "network cleanup".to_owned(),
    });
    assert_eq!(view["kind"], "network-driver-cleanup");
    assert_eq!(view["owner"]["packet_device"]["kind"], "packet-device");
    assert_eq!(view["owner"]["packet_device"]["generation"], 4);
    assert_eq!(view["references"]["io_cleanup"]["kind"], "io-cleanup");
    assert_eq!(view["references"]["driver_binding"]["generation"], 2);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["cancelled_socket_waits"][0]["id"], 90);
    assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 91);
    assert_eq!(view["references"]["revoked_packet_capabilities"][0]["id"], 92);
    assert_eq!(view["cleanup"]["reason"], "device-fault");
    assert_eq!(view["cleanup"]["cancelled_socket_wait_count"], 1);
    assert_eq!(view["last_transition"]["completed_at_event"], 89);
}

#[test]
fn network_generation_audit_view_v1_exposes_exact_generation_refs() {
    let view = network_generation_audit_view_v1(&NetworkGenerationAuditManifest {
        id: 93,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        packet_queue: 89,
        packet_queue_generation: 7,
        packet_descriptor: 90,
        packet_descriptor_generation: 8,
        packet_buffer: 91,
        packet_buffer_generation: 9,
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 92,
            generation: 10,
        },
        device_capability: ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 94,
            generation: 11,
        },
        rejected_packet_generation_probes: 2,
        rejected_dma_generation_probes: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 95,
        note: "generation audit".to_owned(),
    });
    assert_eq!(view["kind"], "network-generation-audit");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer-object");
    assert_eq!(view["references"]["dma_buffer"]["generation"], 10);
    assert_eq!(view["references"]["device_capability"]["kind"], "device-capability");
    assert_eq!(view["audit"]["rejected_packet_generation_probes"], 2);
    assert_eq!(view["audit"]["rejected_dma_generation_probes"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 95);
}

#[test]
fn network_fault_injection_view_v1_exposes_packet_loss_and_error_evidence() {
    let view = network_fault_injection_view_v1(&NetworkFaultInjectionManifest {
        id: 96,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        packet_queue: 89,
        packet_queue_generation: 7,
        packet_descriptor: Some(90),
        packet_descriptor_generation: Some(8),
        packet_buffer: Some(91),
        packet_buffer_generation: Some(9),
        endpoint: Some(92),
        endpoint_generation: Some(10),
        socket: Some(93),
        socket_generation: Some(11),
        owner_store: Some(94),
        owner_store_generation: Some(12),
        direction: "tx".to_owned(),
        kind: "packet-error".to_owned(),
        effect: "report-error".to_owned(),
        injected_packets: 1,
        dropped_packets: 0,
        error_packets: 1,
        error_code: "injected-checksum-error".to_owned(),
        sequence: 18,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 97,
        note: "packet error injection".to_owned(),
    });
    assert_eq!(view["kind"], "network-fault-injection");
    assert_eq!(view["owner"]["adapter"]["kind"], "network-stack-adapter");
    assert_eq!(view["references"]["packet_queue"]["generation"], 7);
    assert_eq!(view["references"]["packet_descriptor"]["generation"], 8);
    assert_eq!(view["references"]["packet_buffer"]["generation"], 9);
    assert_eq!(view["references"]["endpoint"]["generation"], 10);
    assert_eq!(view["injection"]["kind"], "packet-error");
    assert_eq!(view["injection"]["effect"], "report-error");
    assert_eq!(view["injection"]["error_code"], "injected-checksum-error");
    assert_eq!(view["last_transition"]["recorded_at_event"], 97);
}

#[test]
fn network_benchmark_view_v1_exposes_throughput_latency_metrics() {
    let view = network_benchmark_view_v1(&NetworkBenchmarkManifest {
        id: 98,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        tx_queue: 89,
        tx_queue_generation: 7,
        rx_queue: 88,
        rx_queue_generation: 6,
        tx_completion: 99,
        tx_completion_generation: 1,
        rx_wait_resolution: 100,
        rx_wait_resolution_generation: 1,
        endpoint: 92,
        endpoint_generation: 10,
        socket: 93,
        socket_generation: 11,
        owner_store: 94,
        owner_store_generation: 12,
        backpressure: Some(96),
        backpressure_generation: Some(1),
        sample_packets: 3,
        sample_bytes: 6000,
        tx_completed_packets: 1,
        rx_resolved_packets: 1,
        dropped_packets: 1,
        measured_nanos: 120_000,
        budget_nanos: 250_000,
        throughput_bytes_per_sec: 50_000_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 48_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 101,
        note: "network benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "network-benchmark");
    assert_eq!(view["owner"]["adapter"]["generation"], 5);
    assert_eq!(view["references"]["tx_completion"]["kind"], "network-tx-completion");
    assert_eq!(view["references"]["rx_wait_resolution"]["kind"], "network-rx-wait-resolution");
    assert_eq!(view["references"]["backpressure"]["generation"], 1);
    assert_eq!(view["benchmark"]["sample_packets"], 3);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 50_000_000);
    assert_eq!(view["benchmark"]["p99_latency_nanos"], 48_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 101);
}

#[test]
fn network_recovery_benchmark_view_v1_exposes_recovery_metrics() {
    let view = network_recovery_benchmark_view_v1(&NetworkRecoveryBenchmarkManifest {
        id: 99,
        scenario: "host-validation-network-driver-recovery".to_owned(),
        cleanup: 100,
        cleanup_generation: 1,
        io_cleanup: 70,
        io_cleanup_generation: 2,
        adapter: 74,
        adapter_generation: 5,
        packet_device: 51,
        packet_device_generation: 4,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 3,
        },
        driver_store: 7,
        driver_store_generation: 8,
        fault_injection: Some(102),
        fault_injection_generation: Some(1),
        recovery_start_event: 33,
        recovery_complete_event: 34,
        cancelled_socket_waits: 1,
        revoked_packet_capabilities: 1,
        recovery_nanos: 90_000,
        budget_nanos: 200_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 103,
        note: "network recovery benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "network-recovery-benchmark");
    assert_eq!(view["owner"]["driver_store"]["generation"], 8);
    assert_eq!(view["references"]["cleanup"]["kind"], "network-driver-cleanup");
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["fault_injection"]["kind"], "network-fault-injection");
    assert_eq!(view["benchmark"]["recovery_nanos"], 90_000);
    assert_eq!(view["benchmark"]["within_budget"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 103);
}
