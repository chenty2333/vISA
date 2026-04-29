use super::*;

pub(in crate::tests) fn setup_n10_network_stack_adapter_graph() -> SemanticGraph {
    setup_n9_network_tx_completion_graph()
}

#[test]
pub(super) fn network_runtime_n10_smoltcp_adapter_binds_packet_device_contract() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 smoltcp adapter binds packet device".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_stack_adapter_count(), 1);
    let adapter = &graph.network_stack_adapters()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkStackAdapter, 1575, 1)
    );
    assert_eq!(adapter.backend, backend);
    assert_eq!(adapter.packet_device, 1541);
    assert_eq!(adapter.rx_queue, 1544);
    assert_eq!(adapter.tx_queue, 1545);
    assert_eq!(adapter.profile, "smoltcp-0.13.0-ethernet-ipv4-tcp-v1");
    assert_eq!(adapter.socket_capacity, 0);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkStackAdapterBound adapter=1575 implementation=smoltcp")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n10_rejects_stale_profile_queue_and_duplicate_adapter() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let unsupported_profile = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-unknown".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 unsupported profile".to_string(),
        },
    ));
    assert_eq!(unsupported_profile.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_profile.violations,
        vec!["network stack adapter profile is unsupported".to_string()]
    );

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 2,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 stale rx queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network stack adapter rx queue generation is missing or inactive".to_string()]
    );

    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1576,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 duplicate adapter".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network stack adapter packet device already bound".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n10_invariants_reject_adapter_profile_drift() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    graph.corrupt_network_stack_adapter_profile_for_test(1575, "smoltcp-drift");
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkStackAdapterInvalid { adapter: 1575 })
    );
}

pub(in crate::tests) fn setup_n11_socket_object_graph() -> (SemanticGraph, StoreId, Generation) {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    let owner_store = graph.register_store(
        "linux_socket_service",
        "linux-socket-service.fake-aot",
        "service",
        "restartable",
    );
    graph.set_store_state(owner_store, StoreState::Running);
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    (graph, owner_store, owner_store_generation)
}

#[test]
pub(super) fn network_runtime_n11_socket_object_records_adapter_and_store_identity() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 socket object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.socket_object_count(), 1);
    let socket = &graph.socket_objects()[0];
    assert_eq!(
        socket.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SocketObject, 1576, 1)
    );
    assert_eq!(socket.adapter, 1575);
    assert_eq!(socket.adapter_generation, 1);
    assert_eq!(socket.owner_store, owner_store);
    assert_eq!(socket.owner_store_generation, owner_store_generation);
    assert_eq!(socket.domain, 2);
    assert_eq!(socket.socket_type, 1);
    assert_eq!(socket.protocol, 0);
    assert_eq!(socket.canonical_protocol, 6);
    assert_eq!(socket.family, "inet");
    assert_eq!(socket.transport, "tcp");
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("SocketObjectCreated socket=1576 adapter=1575@1")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n11_rejects_stale_adapter_dead_store_and_unsupported_socket() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 2,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["socket object adapter generation is missing or inactive".to_string()]
    );

    let unsupported = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 2,
            protocol: 0,
            note: "n11 unsupported datagram socket".to_string(),
        },
    ));
    assert_eq!(unsupported.status, CommandStatus::Rejected);
    assert_eq!(unsupported.violations, vec!["socket object contract is unsupported".to_string()]);

    graph.set_store_state(owner_store, StoreState::Dead);
    let dead_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let dead_store = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation: dead_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 dead owner store".to_string(),
        },
    ));
    assert_eq!(dead_store.status, CommandStatus::Rejected);
    assert_eq!(dead_store.violations, vec!["socket object owner store is not live".to_string()]);
}

#[test]
pub(super) fn network_runtime_n11_invariants_reject_socket_adapter_generation_leak() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    assert!(graph.record_socket_object_with_id(
        1576,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n11 socket object",
    ));
    graph.corrupt_socket_object_adapter_generation_for_test(1576, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketObjectMissingAdapter { socket: 1576, adapter: 1575 })
    );
}

pub(in crate::tests) fn setup_n12_endpoint_object_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    assert!(graph.record_socket_object_with_id(
        1576,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n11 socket object",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n12_endpoint_object_records_socket_adapter_and_store_identity() {
    let mut graph = setup_n12_endpoint_object_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 endpoint object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.endpoint_object_count(), 1);
    let endpoint = &graph.endpoint_objects()[0];
    assert_eq!(
        endpoint.object_ref(),
        ContractObjectRef::new(ContractObjectKind::EndpointObject, 1577, 1)
    );
    assert_eq!(endpoint.socket, 1576);
    assert_eq!(endpoint.socket_generation, 1);
    assert_eq!(endpoint.adapter, 1575);
    assert_eq!(endpoint.adapter_generation, 1);
    assert_eq!(endpoint.family, "inet");
    assert_eq!(endpoint.transport, "tcp");
    assert_eq!(endpoint.local_addr, [0, 0, 0, 0]);
    assert_eq!(endpoint.local_port, 0);
    assert_eq!(endpoint.remote_addr, [0, 0, 0, 0]);
    assert_eq!(endpoint.remote_port, 0);
    assert_eq!(endpoint.state, EndpointObjectState::Allocated);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("EndpointObjectCreated endpoint=1577 socket=1576@1")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n12_rejects_stale_duplicate_and_pre_n13_bound_endpoint() {
    let mut graph = setup_n12_endpoint_object_graph();
    let stale_socket = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 2,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 stale socket".to_string(),
        },
    ));
    assert_eq!(stale_socket.status, CommandStatus::Rejected);
    assert_eq!(
        stale_socket.violations,
        vec!["endpoint object socket generation is missing or inactive".to_string()]
    );

    let pre_bound = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 pre-bound endpoint".to_string(),
        },
    ));
    assert_eq!(pre_bound.status, CommandStatus::Rejected);
    assert_eq!(
        pre_bound.violations,
        vec!["endpoint object must remain unbound before N13".to_string()]
    );

    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1578,
            socket: 1576,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 duplicate endpoint".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["endpoint object socket generation already has endpoint".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n12_invariants_reject_endpoint_socket_generation_leak() {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    graph.corrupt_endpoint_object_socket_generation_for_test(1577, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::EndpointObjectMissingSocket { endpoint: 1577, socket: 1576 })
    );
}

#[test]
pub(super) fn network_runtime_n12_invariants_reject_duplicate_endpoint_identity() {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    graph.duplicate_endpoint_object_id_for_test(1577, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::EndpointObjectDuplicate { endpoint: 1577 })
    );
}
