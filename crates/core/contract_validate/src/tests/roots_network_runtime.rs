use super::*;

#[test]
fn semantic_roots_reject_network_rx_interrupt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_rx_interrupt_count = 1;
    package.semantic.network_rx_interrupts.push(artifact_manifest::NetworkRxInterruptManifest {
        id: 37,
        virtio_net_backend: 36,
        virtio_net_backend_generation: 1,
        irq_event: 23,
        irq_event_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 73,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network rx interrupt root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_rx_wait_resolution_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_rx_wait_resolution_count = 1;
    package.semantic.network_rx_wait_resolutions.push(
        artifact_manifest::NetworkRxWaitResolutionManifest {
            id: 38,
            io_wait: 24,
            io_wait_generation: 1,
            wait: 44,
            wait_generation: 1,
            rx_interrupt: 37,
            rx_interrupt_generation: 1,
            irq_event: 23,
            irq_event_generation: 1,
            packet_device: 31,
            packet_device_generation: 1,
            rx_queue: 32,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            generation: 1,
            state: "resolved".to_owned(),
            resolved_at_event: 74,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network rx wait resolution root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_tx_capability_gate_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_tx_capability_gate_count = 1;
    package.semantic.network_tx_capability_gates.push(
        artifact_manifest::NetworkTxCapabilityGateManifest {
            id: 39,
            driver_store: 12,
            driver_store_generation: 1,
            packet_device: 31,
            packet_device_generation: 1,
            tx_queue: 33,
            tx_queue_generation: 1,
            packet_descriptor: 34,
            packet_descriptor_generation: 1,
            packet_buffer: 32,
            packet_buffer_generation: 1,
            device_capability: 24,
            device_capability_generation: 1,
            capability: 44,
            capability_generation: 1,
            handle_slot: 1,
            handle_generation: 1,
            handle_tag: 9,
            operation: "tx".to_owned(),
            byte_len: 64,
            sequence: 1,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 75,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network tx capability gate root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_tx_completion_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_tx_completion_count = 1;
    package.semantic.network_tx_completions.push(artifact_manifest::NetworkTxCompletionManifest {
        id: 40,
        tx_gate: 39,
        tx_gate_generation: 1,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 35,
        backend_generation: 1,
        driver_store: 12,
        driver_store_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
        packet_descriptor: 34,
        packet_descriptor_generation: 1,
        packet_buffer: 32,
        packet_buffer_generation: 1,
        byte_len: 64,
        sequence: 1,
        completion_sequence: 1,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 76,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network tx completion root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_stack_adapter_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_stack_adapter_count = 1;
    package.semantic.network_stack_adapters.push(artifact_manifest::NetworkStackAdapterManifest {
        id: 41,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 35,
        backend_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
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
        recorded_at_event: 77,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network stack adapter root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_object_count = 1;
    package.semantic.socket_objects.push(artifact_manifest::SocketObjectManifest {
        id: 42,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 78,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket object root/count mismatch");
}

#[test]
fn semantic_roots_reject_endpoint_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.endpoint_object_count = 1;
    package.semantic.endpoint_objects.push(artifact_manifest::EndpointObjectManifest {
        id: 43,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 79,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "endpoint object root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_operation_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_operation_count = 1;
    package.semantic.socket_operations.push(artifact_manifest::SocketOperationManifest {
        id: 44,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
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
        recorded_at_event: 80,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket operation root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_wait_count = 1;
    package.semantic.socket_waits.push(artifact_manifest::SocketWaitManifest {
        id: 45,
        wait: 46,
        wait_generation: 1,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        wait_kind: "socket-readable".to_owned(),
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 43,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 81,
        completed_at_event: None,
        cancel_reason: None,
        ready_sequence: None,
        byte_len: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_backpressure_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_backpressure_count = 1;
    package.semantic.network_backpressures.push(artifact_manifest::NetworkBackpressureManifest {
        id: 47,
        adapter: 41,
        adapter_generation: 1,
        packet_device: 30,
        packet_device_generation: 1,
        packet_queue: 32,
        packet_queue_generation: 1,
        endpoint: Some(43),
        endpoint_generation: Some(1),
        socket: Some(42),
        socket_generation: Some(1),
        owner_store: Some(7),
        owner_store_generation: Some(1),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 82,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network backpressure root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_driver_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_driver_cleanup_count = 1;
    package.semantic.network_driver_cleanups.push(
        artifact_manifest::NetworkDriverCleanupManifest {
            id: 48,
            io_cleanup: 88,
            io_cleanup_generation: 1,
            driver_store: 9,
            driver_store_generation: 3,
            device: 30,
            device_generation: 1,
            driver_binding: 31,
            driver_binding_generation: 1,
            packet_device: 32,
            packet_device_generation: 1,
            adapter: 33,
            adapter_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 34,
                generation: 1,
            },
            cancelled_socket_waits: Vec::new(),
            cancelled_wait_tokens: Vec::new(),
            revoked_packet_capabilities: Vec::new(),
            generation: 1,
            state: "completed".to_owned(),
            started_at_event: 91,
            completed_at_event: Some(92),
            reason: "device-fault".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network driver cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_generation_audit_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_generation_audit_count = 1;
    package.semantic.network_generation_audits.push(
        artifact_manifest::NetworkGenerationAuditManifest {
            id: 49,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            packet_queue: 32,
            packet_queue_generation: 1,
            packet_descriptor: 33,
            packet_descriptor_generation: 1,
            packet_buffer: 34,
            packet_buffer_generation: 1,
            dma_buffer: artifact_manifest::ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 35,
                generation: 1,
            },
            device_capability: artifact_manifest::ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 36,
                generation: 1,
            },
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 93,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network generation audit root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_fault_injection_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_fault_injection_count = 1;
    package.semantic.network_fault_injections.push(
        artifact_manifest::NetworkFaultInjectionManifest {
            id: 50,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            packet_queue: 32,
            packet_queue_generation: 1,
            packet_descriptor: Some(33),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(34),
            packet_buffer_generation: Some(1),
            endpoint: Some(43),
            endpoint_generation: Some(1),
            socket: Some(42),
            socket_generation: Some(1),
            owner_store: Some(7),
            owner_store_generation: Some(1),
            direction: "tx".to_owned(),
            kind: "packet-loss".to_owned(),
            effect: "drop-packet".to_owned(),
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 94,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network fault injection root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_benchmark_count = 1;
    package.semantic.network_benchmarks.push(artifact_manifest::NetworkBenchmarkManifest {
        id: 51,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 41,
        adapter_generation: 1,
        packet_device: 30,
        packet_device_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        tx_completion: 40,
        tx_completion_generation: 1,
        rx_wait_resolution: 38,
        rx_wait_resolution_generation: 1,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        backpressure: Some(47),
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
        recorded_at_event: 95,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_recovery_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_recovery_benchmark_count = 1;
    package.semantic.network_recovery_benchmarks.push(
        artifact_manifest::NetworkRecoveryBenchmarkManifest {
            id: 52,
            scenario: "host-validation-network-driver-recovery".to_owned(),
            cleanup: 46,
            cleanup_generation: 1,
            io_cleanup: 32,
            io_cleanup_generation: 1,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 35,
                generation: 1,
            },
            driver_store: 7,
            driver_store_generation: 1,
            fault_injection: Some(48),
            fault_injection_generation: Some(1),
            recovery_start_event: 80,
            recovery_complete_event: 90,
            cancelled_socket_waits: 1,
            revoked_packet_capabilities: 1,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 96,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network recovery benchmark root/count mismatch");
}
