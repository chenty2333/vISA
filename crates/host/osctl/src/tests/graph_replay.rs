use super::*;

#[test]
fn graph_json_edges_separate_live_history_and_cleanup_modes() {
    let mut package = minimal_graph_package();
    package.semantic.activation_records.push(ActivationRecordManifest {
        id: 10,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        entry: "_start".to_owned(),
        generation: 6,
        state: "running".to_owned(),
        start_event: 7,
        ..ActivationRecordManifest::default()
    });
    package.semantic.code_objects.push(CodeObjectManifest {
        id: 3,
        artifact_id: 5,
        package: "driver".to_owned(),
        owner_profile: "host-validation".to_owned(),
        generation: 4,
        state: "bound-to-store".to_owned(),
        bound_store: Some(1),
        bound_store_generation: Some(2),
        ..CodeObjectManifest::default()
    });
    package.semantic.capability_records.push(CapabilityRecordManifest {
        id: 20,
        subject: "driver".to_owned(),
        object: "packet-device.net0".to_owned(),
        object_ref: Some(AuthorityObjectRefManifest {
            scope: "internal".to_owned(),
            class: "packet-device".to_owned(),
            object: ContractObjectRefManifest {
                kind: "resource".to_owned(),
                id: 99,
                generation: 1,
            },
        }),
        rights: vec!["rx".to_owned()],
        lifetime: "store".to_owned(),
        class: "packet-device".to_owned(),
        owner_store: Some(1),
        owner_store_generation: Some(2),
        source: "test".to_owned(),
        generation: 1,
        manifest_decl: true,
        ..CapabilityRecordManifest::default()
    });
    package.semantic.wait_records.push(WaitRecordManifest {
        id: 30,
        owner_store: Some(1),
        owner_store_generation: Some(2),
        kind: "device-irq".to_owned(),
        generation: 1,
        state: "pending".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        restart_policy: "restart-if-allowed".to_owned(),
        ..WaitRecordManifest::default()
    });
    package.semantic.trap_records.push(TrapRecordManifest {
        id: 40,
        generation: 1,
        class: "capability-trap".to_owned(),
        store: Some(1),
        store_generation: Some(2),
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        artifact: Some(5),
        artifact_generation: Some(1),
        fault_policy: "restart".to_owned(),
        effect: "cleanup".to_owned(),
        detail: "denied".to_owned(),
        ..TrapRecordManifest::default()
    });
    package.semantic.hostcall_trace.push(HostcallTraceManifest {
        id: 50,
        generation: 1,
        activation: 10,
        activation_generation: 6,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        artifact_generation: 7,
        hostcall_number: 1,
        name: "hostcall.packet-device.net0.rx".to_owned(),
        category: "packet-device".to_owned(),
        object: "packet-device.net0".to_owned(),
        operation: "rx".to_owned(),
        allowed: true,
        result: "complete".to_owned(),
        trap_out: Some(40),
        trap_generation_out: Some(1),
        ..HostcallTraceManifest::default()
    });
    package.semantic.cleanup_transactions.push(CleanupTransactionManifest {
        id: 60,
        store: 1,
        store_generation: 2,
        target_store_generation: 2,
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        generation: 1,
        started_at: 8,
        finished_at: Some(9),
        state: "completed".to_owned(),
        reason: "fault".to_owned(),
        released_dmw_leases: 0,
        cancelled_waits: 1,
        revoked_capabilities: vec![20],
        revoked_capability_refs: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        dropped_resources: 0,
        unbound_code_object: true,
        state_digest: "store:1@3:dead|code:3@4:retired|activations=[]|leases=[]|caps=[]".to_owned(),
        effect: "restart".to_owned(),
        steps: Vec::new(),
        effects: Vec::new(),
        result_store_generation: Some(3),
    });
    package.semantic.io_cleanups.push(IoCleanupManifest {
        id: 70,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "device-fault".to_owned(),
        started_at_event: 10,
        completed_at_event: 11,
        cancelled_io_waits: vec![ContractObjectRefManifest {
            kind: "io-wait".to_owned(),
            id: 46,
            generation: 1,
        }],
        revoked_device_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        }],
        revoked_capabilities: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 20,
            generation: 1,
        }],
        released_dma_buffers: vec![ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 38,
            generation: 1,
        }],
        released_mmio_regions: vec![ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 39,
            generation: 1,
        }],
        released_irq_lines: vec![ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        }],
        steps: Vec::new(),
        note: "io cleanup graph".to_owned(),
    });
    package.semantic.io_fault_injections.push(IoFaultInjectionManifest {
        id: 71,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        target: ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        },
        cleanup: 70,
        cleanup_generation: 1,
        generation: 1,
        kind: "device-fault".to_owned(),
        state: "completed".to_owned(),
        injected_at_event: 12,
        note: "io fault graph".to_owned(),
    });
    package.semantic.packet_buffer_objects.push(PacketBufferObjectManifest {
        id: 80,
        packet_device: 81,
        packet_device_generation: 1,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 1,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 13,
        note: "packet buffer graph".to_owned(),
    });
    package.semantic.packet_queue_objects.push(PacketQueueObjectManifest {
        id: 82,
        name: "net0-rx0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 14,
        note: "packet queue graph".to_owned(),
    });
    package.semantic.packet_descriptors.push(PacketDescriptorObjectManifest {
        id: 83,
        packet_queue: 82,
        packet_queue_generation: 1,
        packet_buffer: 80,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 15,
        note: "packet descriptor graph".to_owned(),
    });
    package.semantic.fake_net_backends.push(FakeNetBackendObjectManifest {
        id: 84,
        name: "fake-net0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
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
        recorded_at_event: 16,
        note: "fake net backend graph".to_owned(),
    });
    package.semantic.virtio_net_backends.push(VirtioNetBackendObjectManifest {
        id: 85,
        name: "virtio-net0-backend".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        driver_binding: 70,
        driver_binding_generation: 1,
        device: 61,
        device_generation: 1,
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
        recorded_at_event: 17,
        note: "virtio net backend graph".to_owned(),
    });
    package.semantic.network_rx_interrupts.push(NetworkRxInterruptManifest {
        id: 86,
        virtio_net_backend: 85,
        virtio_net_backend_generation: 1,
        irq_event: 41,
        irq_event_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 18,
        note: "network rx interrupt graph".to_owned(),
    });
    package.semantic.network_rx_wait_resolutions.push(NetworkRxWaitResolutionManifest {
        id: 87,
        io_wait: 50,
        io_wait_generation: 1,
        wait: 5,
        wait_generation: 1,
        rx_interrupt: 86,
        rx_interrupt_generation: 1,
        irq_event: 41,
        irq_event_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "resolved".to_owned(),
        resolved_at_event: 19,
        note: "network rx wait resolution graph".to_owned(),
    });
    package.semantic.packet_buffer_objects.push(PacketBufferObjectManifest {
        id: 88,
        packet_device: 81,
        packet_device_generation: 1,
        direction: "tx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 2,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 20,
        note: "tx packet buffer graph".to_owned(),
    });
    package.semantic.packet_queue_objects.push(PacketQueueObjectManifest {
        id: 89,
        name: "net0-tx0".to_owned(),
        packet_device: 81,
        packet_device_generation: 1,
        role: "tx".to_owned(),
        queue_index: 1,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 21,
        note: "tx packet queue graph".to_owned(),
    });
    package.semantic.packet_descriptors.push(PacketDescriptorObjectManifest {
        id: 90,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 22,
        note: "tx packet descriptor graph".to_owned(),
    });
    package.semantic.network_tx_capability_gates.push(NetworkTxCapabilityGateManifest {
        id: 91,
        driver_store: 1,
        driver_store_generation: 2,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        packet_descriptor: 90,
        packet_descriptor_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        device_capability: 42,
        device_capability_generation: 1,
        capability: 1,
        capability_generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 9,
        operation: "tx".to_owned(),
        byte_len: 64,
        sequence: 2,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 23,
        note: "network tx capability gate graph".to_owned(),
    });
    package.semantic.network_tx_completions.push(NetworkTxCompletionManifest {
        id: 92,
        tx_gate: 91,
        tx_gate_generation: 1,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 85,
        backend_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        packet_descriptor: 90,
        packet_descriptor_generation: 1,
        packet_buffer: 88,
        packet_buffer_generation: 1,
        byte_len: 64,
        sequence: 2,
        completion_sequence: 1,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 24,
        note: "network tx completion graph".to_owned(),
    });
    package.semantic.network_stack_adapters.push(NetworkStackAdapterManifest {
        id: 93,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 85,
        backend_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        ipv4_addr: [10, 0, 2, 15],
        ipv4_prefix_len: 24,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        max_payload_len: 512,
        socket_capacity: 0,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 25,
        note: "network stack adapter graph".to_owned(),
    });
    package.semantic.socket_objects.push(SocketObjectManifest {
        id: 94,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 26,
        note: "socket object graph".to_owned(),
    });
    package.semantic.endpoint_objects.push(EndpointObjectManifest {
        id: 95,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 27,
        note: "endpoint object graph".to_owned(),
    });
    package.semantic.socket_operations.push(SocketOperationManifest {
        id: 96,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        operation: "bind".to_owned(),
        local_addr: [10, 0, 2, 15],
        local_port: 8080,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        backlog: 0,
        byte_len: 0,
        sequence: 1,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 28,
        note: "socket operation graph".to_owned(),
    });
    package.semantic.socket_waits.push(SocketWaitManifest {
        id: 97,
        wait: 45,
        wait_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 95,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 29,
        completed_at_event: None,
        cancel_reason: None,
        ready_sequence: None,
        byte_len: None,
        note: "pending socket wait graph".to_owned(),
    });
    package.semantic.socket_waits.push(SocketWaitManifest {
        id: 98,
        wait: 46,
        wait_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        wait_kind: "socket-readable".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 95,
            generation: 1,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 30,
        completed_at_event: Some(31),
        cancel_reason: None,
        ready_sequence: Some(1),
        byte_len: Some(19),
        note: "resolved socket wait graph".to_owned(),
    });
    package.semantic.network_backpressures.push(NetworkBackpressureManifest {
        id: 99,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        endpoint: Some(95),
        endpoint_generation: Some(1),
        socket: Some(94),
        socket_generation: Some(1),
        owner_store: Some(1),
        owner_store_generation: Some(2),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 2,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 32,
        note: "network backpressure graph".to_owned(),
    });
    package.semantic.network_driver_cleanups.push(NetworkDriverCleanupManifest {
        id: 100,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 1,
        },
        cancelled_socket_waits: vec![ContractObjectRefManifest {
            kind: "socket-wait".to_owned(),
            id: 97,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 45,
            generation: 1,
        }],
        revoked_packet_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 33,
        completed_at_event: Some(34),
        reason: "device-fault".to_owned(),
        note: "network driver cleanup graph".to_owned(),
    });
    package.semantic.network_generation_audits.push(NetworkGenerationAuditManifest {
        id: 101,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_descriptor: 88,
        packet_descriptor_generation: 1,
        packet_buffer: 87,
        packet_buffer_generation: 1,
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 50,
            generation: 1,
        },
        device_capability: ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 42,
            generation: 1,
        },
        rejected_packet_generation_probes: 2,
        rejected_dma_generation_probes: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 35,
        note: "network generation audit graph".to_owned(),
    });
    package.semantic.network_fault_injections.push(NetworkFaultInjectionManifest {
        id: 102,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        packet_queue: 89,
        packet_queue_generation: 1,
        packet_descriptor: Some(88),
        packet_descriptor_generation: Some(1),
        packet_buffer: Some(87),
        packet_buffer_generation: Some(1),
        endpoint: Some(95),
        endpoint_generation: Some(1),
        socket: Some(94),
        socket_generation: Some(1),
        owner_store: Some(7),
        owner_store_generation: Some(2),
        direction: "tx".to_owned(),
        kind: "packet-loss".to_owned(),
        effect: "drop-packet".to_owned(),
        injected_packets: 1,
        dropped_packets: 1,
        error_packets: 0,
        error_code: String::new(),
        sequence: 18,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 36,
        note: "network fault injection graph".to_owned(),
    });
    package.semantic.network_benchmarks.push(NetworkBenchmarkManifest {
        id: 103,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        tx_queue: 89,
        tx_queue_generation: 1,
        rx_queue: 82,
        rx_queue_generation: 1,
        tx_completion: 92,
        tx_completion_generation: 1,
        rx_wait_resolution: 87,
        rx_wait_resolution_generation: 1,
        endpoint: 95,
        endpoint_generation: 1,
        socket: 94,
        socket_generation: 1,
        owner_store: 7,
        owner_store_generation: 2,
        backpressure: Some(99),
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
        recorded_at_event: 37,
        note: "network benchmark graph".to_owned(),
    });
    package.semantic.network_recovery_benchmarks.push(NetworkRecoveryBenchmarkManifest {
        id: 104,
        scenario: "host-validation-network-driver-recovery".to_owned(),
        cleanup: 100,
        cleanup_generation: 1,
        io_cleanup: 70,
        io_cleanup_generation: 1,
        adapter: 93,
        adapter_generation: 1,
        packet_device: 81,
        packet_device_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 85,
            generation: 1,
        },
        driver_store: 1,
        driver_store_generation: 2,
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
        recorded_at_event: 38,
        note: "network recovery benchmark graph".to_owned(),
    });
    package.semantic.block_device_objects.push(BlockDeviceObjectManifest {
        id: 105,
        name: "blk0".to_owned(),
        device: 35,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 39,
        note: "block device graph".to_owned(),
    });
    package.semantic.block_range_objects.push(BlockRangeObjectManifest {
        id: 106,
        block_device: 105,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 40,
        note: "block range graph".to_owned(),
    });
    package.semantic.block_request_objects.push(BlockRequestObjectManifest {
        id: 107,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 41,
        note: "block request graph".to_owned(),
    });
    package.semantic.block_completion_objects.push(BlockCompletionObjectManifest {
        id: 108,
        block_request: 107,
        block_request_generation: 1,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        status: "success".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 42,
        note: "block completion graph".to_owned(),
    });
    package.semantic.block_waits.push(BlockWaitManifest {
        id: 109,
        wait: 110,
        wait_generation: 1,
        block_request: 107,
        block_request_generation: 1,
        block_device: 105,
        block_device_generation: 1,
        block_range: 106,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 43,
        completed_at_event: Some(44),
        completion: Some(108),
        completion_generation: Some(1),
        cancel_reason: None,
        note: "block wait graph".to_owned(),
    });
    package.semantic.fake_block_backends.push(FakeBlockBackendObjectManifest {
        id: 111,
        name: "fake-block0".to_owned(),
        block_device: 105,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 7,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 45,
        note: "fake block backend graph".to_owned(),
    });
    package.semantic.virtio_blk_backends.push(VirtioBlkBackendObjectManifest {
        id: 112,
        name: "virtio-blk0-backend".to_owned(),
        block_device: 105,
        block_device_generation: 1,
        driver_binding: 113,
        driver_binding_generation: 1,
        device: 103,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-blk-backend-skeleton-v1".to_owned(),
        model: "virtio-blk".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        device_features: 0x40,
        driver_features: 0x40,
        negotiated_features: 0x40,
        request_queue_index: 0,
        queue_size: 8,
        irq_vector: 6,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 46,
        note: "virtio block backend graph".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "owns"
        && edge["to"]["kind"] == "activation"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "authorizes"
        && edge["to"]["kind"] == "resource"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "packet-descriptor->packet-queue"
        && edge["from"]["kind"] == "packet-descriptor"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "packet-descriptor->packet-buffer"
        && edge["from"]["kind"] == "packet-descriptor"
        && edge["to"]["kind"] == "packet-buffer"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-device->device"
        && edge["from"]["kind"] == "block-device"
        && edge["to"]["kind"] == "device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-range->block-device"
        && edge["from"]["kind"] == "block-range"
        && edge["to"]["kind"] == "block-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "block-request->block-range"
        && edge["from"]["kind"] == "block-request"
        && edge["to"]["kind"] == "block-range"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "fake-block-backend->block-device"
        && edge["from"]["kind"] == "fake-block-backend"
        && edge["to"]["kind"] == "block-device"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-blk-backend->block-device"
        && edge["from"]["kind"] == "virtio-blk-backend"
        && edge["to"]["kind"] == "block-device"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-blk-backend->driver-binding"
        && edge["from"]["kind"] == "virtio-blk-backend"
        && edge["to"]["kind"] == "driver-store-binding"));
    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "block-completion->block-request"
        && edge["from"]["kind"] == "block-completion"
        && edge["to"]["kind"] == "block-request"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "block-wait->block-completion"
        && edge["from"]["kind"] == "block-wait"
        && edge["to"]["kind"] == "block-completion"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "fake-net-backend->packet-device"
        && edge["from"]["kind"] == "fake-net-backend"
        && edge["to"]["kind"] == "packet-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-net-backend->packet-device"
        && edge["from"]["kind"] == "virtio-net-backend"
        && edge["to"]["kind"] == "packet-device"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "virtio-net-backend->driver-binding"
        && edge["from"]["kind"] == "virtio-net-backend"
        && edge["to"]["kind"] == "driver-store-binding"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-rx-interrupt->virtio-net-backend"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "virtio-net-backend"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-rx-interrupt->rx-queue"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->backend"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "virtio-net-backend"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->rx-queue"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 82));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "network-stack-adapter->tx-queue"
        && edge["from"]["kind"] == "network-stack-adapter"
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 89));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-object->network-stack-adapter"
        && edge["from"]["kind"] == "socket-object"
        && edge["to"]["kind"] == "network-stack-adapter"
        && edge["to"]["id"] == 93));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-object->owner-store"
        && edge["from"]["kind"] == "socket-object"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->socket-object"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "socket-object"
        && edge["to"]["id"] == 94));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->network-stack-adapter"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "network-stack-adapter"
        && edge["to"]["id"] == 93));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "endpoint-object->owner-store"
        && edge["from"]["kind"] == "endpoint-object"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-wait->wait-token"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 97
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(live.iter().any(|edge| edge["mode"] == "live"
        && edge["relation"] == "socket-wait->endpoint-object"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 97
        && edge["to"]["kind"] == "endpoint-object"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-backpressure"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-driver-cleanup"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-generation-audit"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-fault-injection"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-benchmark"));
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "network-recovery-benchmark"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->endpoint-object"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->socket-object"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "socket-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->network-stack-adapter"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "network-stack-adapter"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-operation->owner-store"
        && edge["from"]["kind"] == "socket-operation"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-wait->wait-token"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 98
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "socket-wait->endpoint-object"
        && edge["from"]["kind"] == "socket-wait"
        && edge["from"]["id"] == 98
        && edge["to"]["kind"] == "endpoint-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-backpressure->packet-queue"
        && edge["from"]["kind"] == "network-backpressure"
        && edge["from"]["id"] == 99
        && edge["to"]["kind"] == "packet-queue"
        && edge["to"]["id"] == 89));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-backpressure->endpoint-object"
        && edge["from"]["kind"] == "network-backpressure"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-driver-cleanup->io-cleanup"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "io-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-driver-cleanup->backend"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "virtio-net-backend-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->cancelled-socket-wait"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "socket-wait"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->cancelled-wait-token"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "wait-token"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "network-driver-cleanup->revoked-packet-capability"
        && edge["from"]["kind"] == "network-driver-cleanup"
        && edge["to"]["kind"] == "device-capability"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->packet-descriptor"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->dma-buffer"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "dma-buffer-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-generation-audit->device-capability"
        && edge["from"]["kind"] == "network-generation-audit"
        && edge["to"]["kind"] == "device-capability"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->packet-descriptor"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->endpoint-object"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "endpoint-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-fault-injection->owner-store"
        && edge["from"]["kind"] == "network-fault-injection"
        && edge["to"]["kind"] == "store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->tx-completion"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-tx-completion"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->rx-wait-resolution"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-benchmark->network-backpressure"
        && edge["from"]["kind"] == "network-benchmark"
        && edge["to"]["kind"] == "network-backpressure"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->network-driver-cleanup"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "network-driver-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->network-fault-injection"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "network-fault-injection"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-recovery-benchmark->backend"
        && edge["from"]["kind"] == "network-recovery-benchmark"
        && edge["to"]["kind"] == "virtio-net-backend-object"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-interrupt->irq-event"
        && edge["from"]["kind"] == "network-rx-interrupt"
        && edge["to"]["kind"] == "irq-event"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-wait-resolution->rx-interrupt"
        && edge["from"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["kind"] == "network-rx-interrupt"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-rx-wait-resolution->rx-queue"
        && edge["from"]["kind"] == "network-rx-wait-resolution"
        && edge["to"]["kind"] == "packet-queue"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-capability-gate->packet-descriptor"
        && edge["from"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["kind"] == "packet-descriptor"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-capability-gate->capability"
        && edge["from"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["kind"] == "capability"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->tx-gate"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "network-tx-capability-gate"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->backend"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "virtio-net-backend"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["relation"] == "network-tx-completion->packet-descriptor"
        && edge["from"]["kind"] == "network-tx-completion"
        && edge["to"]["kind"] == "packet-descriptor"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["to"]["kind"] == "activation"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["to"]["kind"] == "artifact"
        && edge["to"]["generation"] == 7));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "hostcall"
        && edge["relation"] == "caused"
        && edge["to"]["kind"] == "trap"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["relation"] == "revoked"
        && edge["to"]["kind"] == "capability"));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["from"]["kind"] == "io-cleanup"
        && edge["relation"] == "released-irq-line"
        && edge["to"]["kind"] == "irq-line-object"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "io-cleanup"
        && edge["relation"] == "io-cleanup-driver-store"
        && edge["to"]["generation"] == 2));
    assert!(history.iter().any(|edge| edge["mode"] == "cleanup-effect"
        && edge["from"]["kind"] == "io-fault-injection"
        && edge["relation"] == "triggered-cleanup"
        && edge["to"]["kind"] == "io-cleanup"));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "io-fault-injection"
        && edge["relation"] == "io-fault-target"
        && edge["to"]["kind"] == "irq-line-object"));
}

#[test]
fn substrate_profile_selection_is_stable_for_json_checks() {
    let host = substrate_capabilities_for_profile("host-validation").expect("host profile");
    let semantic =
        substrate_capabilities_for_profile("semantic-harness").expect("semantic profile");

    assert!(host.artifact_loading);
    assert_eq!(host.dmw.as_str(), "logical");
    assert!(host.mmio);
    assert_eq!(host.snapshot.as_str(), "deterministic-replay");
    assert!(!semantic.artifact_loading);
    assert_eq!(semantic.dma.as_str(), "none");
    assert!(substrate_capabilities_for_profile("unknown-profile").is_none());
}

#[test]
fn interface_profile_selection_is_stable_for_json_checks() {
    let host = interface_capabilities_for_profile("host-validation").expect("host profile");
    let none = interface_capabilities_for_profile("none").expect("none profile");

    assert!(host.custom_wit_worlds.iter().any(|world| world == "semantic:machine"));
    assert!(none.custom_wit_worlds.is_empty());
    assert!(interface_capabilities_for_profile("unknown-profile").is_none());
}

#[test]
fn replay_fixtures_replay_to_expected_final_views() {
    let wait = parse_replay_fixture(replay_fixtures::WAIT_PENDING_RESUME);
    replay_wait_fixture(&wait);

    let capability = parse_replay_fixture(replay_fixtures::CAPABILITY_REVOKE_GENERATION);
    replay_capability_fixture(&capability);

    let cleanup = parse_replay_fixture(replay_fixtures::DRIVER_FAULT_CLEANUP_GENERATION_SAFE);
    replay_cleanup_fixture(&cleanup);
}

fn parse_replay_fixture(source: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(source).expect("replay fixture JSON");
    assert_eq!(value["schema"], "vmos-replay-fixture-v1");
    assert!(!value["commands"].as_array().expect("commands").is_empty());
    assert!(!value["events"].as_array().expect("events").is_empty());
    assert!(value["validation"]["ok"].as_bool().expect("validation ok"));
    value
}

fn replay_wait_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.register_store("bootstrap_a", "bootstrap_a.cwasm", "service", "restartable");
    graph.register_store("bootstrap_b", "bootstrap_b.cwasm", "service", "restartable");
    let owner_store = 3;
    let owner_store_generation = 1;
    let registered_store =
        graph.register_store("timer_service", "timer.cwasm", "service", "restartable");
    assert_eq!(registered_store, owner_store);
    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "CreateWait" => graph
                .apply(SemanticCommand::CreateWait {
                    wait: command["wait"].as_u64().expect("wait"),
                    owner_task: command["owner_task"].as_u64().map(|task| task as u32),
                    owner_store: command["owner_store"].as_u64(),
                    owner_store_generation: Some(
                        command["owner_store_generation"]
                            .as_u64()
                            .unwrap_or(owner_store_generation),
                    ),
                    kind: SemanticWaitKind::Timer,
                    generation: command["generation"].as_u64().expect("generation"),
                    blockers: Vec::new(),
                    deadline: command["deadline"].as_u64(),
                    restart_policy: RestartPolicy::RestartWithAdjustedTimeout,
                    saved_context: None,
                })
                .expect("create wait"),
            "ResolveWait" => graph
                .apply(SemanticCommand::ResolveWait {
                    wait: command["wait"].as_u64().expect("wait"),
                    reason: command["reason"].as_str().expect("reason").to_owned(),
                })
                .expect("resolve wait"),
            "ConsumeWait" => {
                graph.record_wait_consumed(command["wait"].as_u64().expect("wait"));
                continue;
            }
            other => panic!("unsupported wait replay fixture command {other}"),
        };
    }
    let wait = graph.wait_records().iter().find(|wait| wait.id == 21).expect("wait 21");
    assert_eq!(wait.state, WaitState::Consumed);
    assert_eq!(value["final_views"]["wait"]["state"], wait.state.as_str());
    let snapshot = ContractGraphSnapshot {
        waits: graph.wait_records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

fn replay_capability_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
    let object = ContractObjectRef::new(ContractObjectKind::Resource, 99, 1);
    let authority = AuthorityObjectRef::internal(CapabilityClass::PacketDevice, object);
    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "GrantCapability" => {
                graph
                    .apply(SemanticCommand::GrantCapability {
                        subject: command["subject"].as_str().expect("subject").to_owned(),
                        debug_object_label: "packet-device.net0".to_owned(),
                        object_ref: authority,
                        operations: vec!["rx".to_owned(), "tx".to_owned()],
                        lifetime: "store".to_owned(),
                        owner_store: command["owner_store"].as_u64().or(Some(store)),
                        owner_store_generation: command["owner_store_generation"]
                            .as_u64()
                            .or(Some(1)),
                        owner_task: None,
                        source: "replay-fixture".to_owned(),
                        manifest_decl: true,
                    })
                    .expect("grant capability");
            }
            "CreateWait" => {
                graph
                    .apply(SemanticCommand::CreateWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        owner_task: None,
                        owner_store: command["owner_store"].as_u64().or(Some(store)),
                        owner_store_generation: command["owner_store_generation"]
                            .as_u64()
                            .or(Some(1)),
                        kind: SemanticWaitKind::DeviceIrq,
                        generation: 1,
                        blockers: vec![ContractObjectRef::new(
                            ContractObjectKind::Capability,
                            command["blocker"]["id"].as_u64().expect("cap blocker"),
                            command["blocker"]["generation"].as_u64().expect("cap generation"),
                        )],
                        deadline: None,
                        restart_policy: RestartPolicy::RestartIfAllowed,
                        saved_context: None,
                    })
                    .expect("create wait");
            }
            "RevokeCapability" => {
                graph
                    .apply(SemanticCommand::RevokeCapability {
                        cap: command["cap"].as_u64().expect("cap"),
                    })
                    .expect("revoke capability");
            }
            "CancelWait" => {
                graph
                    .apply(SemanticCommand::CancelWait {
                        wait: command["wait"].as_u64().expect("wait"),
                        errno: 125,
                        reason: WaitCancelReason::CapabilityRevoked,
                    })
                    .expect("cancel wait");
            }
            other => panic!("unsupported capability replay fixture command {other}"),
        }
    }

    let cap = graph.capabilities().records()[0].clone();
    assert!(cap.revoked);
    assert_eq!(cap.generation, 2);
    assert_eq!(value["final_views"]["capability"]["id"], cap.id);
    let wait = graph.wait_records().iter().find(|wait| wait.id == 22).expect("wait 22");
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::CapabilityRevoked));
    let snapshot = ContractGraphSnapshot {
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        waits: graph.wait_records().to_vec(),
        external_objects: vec![ExternalObjectDeclaration::new(
            object,
            "replay-fixture",
            CapabilityClass::PacketDevice.as_str(),
            "packet-device.net0",
        )],
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
    assert_eq!(value["expected_violation_codes"][0], "revoked");
}

fn replay_cleanup_fixture(value: &serde_json::Value) {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver_virtio_net", "driver.cwasm", "driver", "restartable");
    assert_eq!(store, 1);
    let mut last_rebind_generation = 1;
    let mut applied_step_status = None;

    for command in value["commands"].as_array().expect("commands") {
        match command["op"].as_str().expect("op") {
            "BeginCleanup" => {
                let target = &command["target_store"];
                assert_eq!(target["id"].as_u64().expect("target id"), store);
                graph
                    .apply(SemanticCommand::BeginCleanup {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                        store,
                        generation: target["generation"].as_u64().expect("generation"),
                        reason: command["reason"].as_str().expect("reason").to_owned(),
                    })
                    .expect("begin cleanup");
            }
            "RebindStore" => {
                let expected = &command["store"];
                assert_eq!(expected["id"].as_u64().expect("store id"), store);
                let rebound = graph.rebind_store_instance(store).expect("rebind store");
                last_rebind_generation = rebound.generation;
                assert_eq!(
                    expected["generation"].as_u64().expect("store generation"),
                    rebound.generation
                );
                assert_eq!(
                    expected["state"].as_str().expect("state"),
                    graph.stores()[0].state.as_str()
                );
            }
            "ApplyCleanupStep" => {
                let target = object_ref_from_json(&command["target"]);
                let observed_generation =
                    command["observed_generation"].as_u64().expect("observed generation");
                if command["status"].as_str() == Some("skipped-stale-generation") {
                    assert_ne!(target.generation, observed_generation);
                }
                graph
                    .apply(SemanticCommand::ApplyCleanupStep {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                        step: cleanup_step_from_json(command["step"].as_str().expect("step")),
                        target,
                        observed_generation,
                    })
                    .expect("apply cleanup step");
                applied_step_status = command["status"].as_str().map(|status| status.to_owned());
            }
            "CommitCleanup" => {
                graph
                    .apply(SemanticCommand::CommitCleanup {
                        cleanup: command["cleanup"].as_u64().expect("cleanup"),
                    })
                    .expect("commit cleanup");
                if let Some(status) = command["status"].as_str() {
                    assert_eq!(applied_step_status.as_deref(), Some(status));
                }
            }
            other => panic!("unsupported cleanup replay fixture command {other}"),
        }
    }

    assert_eq!(last_rebind_generation, 2);
    assert_eq!(
        graph.stores()[0].state.as_str(),
        value["final_views"]["store"]["state"].as_str().expect("store state")
    );
    assert_eq!(value["final_views"]["store"]["generation"], graph.stores()[0].generation);
    for event in value["events"].as_array().expect("events") {
        match event["kind"].as_str().expect("event kind") {
            "CleanupStepApplied" => {
                let expected = format!(
                    "CleanupStepApplied cleanup={} step={} target={} observed_generation={}",
                    event["cleanup"].as_u64().expect("cleanup"),
                    event["step"].as_str().expect("step"),
                    event["target"].as_str().expect("target"),
                    event["observed_generation"].as_u64().expect("observed generation")
                );
                assert!(
                    graph
                        .event_log_tail(16)
                        .iter()
                        .any(|record| record.summary().contains(&expected)),
                    "missing expected event {expected}"
                );
            }
            "StoreRebound" => {
                assert_eq!(
                    event["store"].as_str().expect("store"),
                    format!("{}@{}", store, graph.stores()[0].generation)
                );
            }
            "FaultCleanupStarted" | "FaultCleanupSkipped" => {}
            other => panic!("unsupported cleanup replay fixture event {other}"),
        }
    }
    let digest = cleanup_replay_digest(&graph, store);
    assert_eq!(value["state_digest"]["cleanup_once"], digest);
    assert_eq!(value["state_digest"]["cleanup_once"], value["state_digest"]["cleanup_twice"]);
}

fn object_ref_from_json(value: &serde_json::Value) -> ContractObjectRef {
    let kind = match value["kind"].as_str().expect("object kind") {
        "store" => ContractObjectKind::Store,
        "capability" => ContractObjectKind::Capability,
        "wait-token" | "wait" => ContractObjectKind::WaitToken,
        "cleanup" | "cleanup-transaction" => ContractObjectKind::CleanupTransaction,
        "resource" => ContractObjectKind::Resource,
        other => panic!("unsupported replay fixture object kind {other}"),
    };
    ContractObjectRef::new(
        kind,
        value["id"].as_u64().expect("object id"),
        value["generation"].as_u64().expect("object generation"),
    )
}

fn cleanup_step_from_json(value: &str) -> CleanupStep {
    match value {
        "stop-new-activation" => CleanupStep::StopNewActivation,
        "seal-activation" => CleanupStep::SealActivation,
        "prevent-hostcalls" => CleanupStep::PreventHostcalls,
        "release-dmw-leases" => CleanupStep::ReleaseDmwLeases,
        "cancel-wait-tokens" => CleanupStep::CancelWaitTokens,
        "revoke-capabilities" => CleanupStep::RevokeCapabilities,
        "drop-resource-arena" => CleanupStep::DropResourceArena,
        "unbind-code-object" => CleanupStep::UnbindCodeObject,
        "mark-store-state" => CleanupStep::MarkStoreState,
        "record-transition" => CleanupStep::RecordTransition,
        "emit-tombstones" => CleanupStep::EmitTombstones,
        "record-failure-effect" => CleanupStep::RecordFailureEffect,
        "emit-report" => CleanupStep::EmitReport,
        other => panic!("unsupported cleanup step {other}"),
    }
}

fn cleanup_replay_digest(graph: &SemanticGraph, store: u64) -> String {
    let store = graph.stores().iter().find(|record| record.id == store).expect("digest store");
    format!(
        "store:{}@{}:{}|code:1@1:bound|caps:active",
        store.id,
        store.generation,
        store.state.as_str()
    )
}
