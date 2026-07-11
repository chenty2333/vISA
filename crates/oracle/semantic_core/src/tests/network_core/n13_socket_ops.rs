use super::*;

pub(in crate::tests) fn setup_n13_socket_operation_graph()
-> (SemanticGraph, EndpointObjectId, EndpointObjectId) {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 listen endpoint",
    ));
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    assert!(graph.record_socket_object_with_id(
        1580,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n13 connected socket object",
    ));
    assert!(graph.record_endpoint_object_with_id(
        1581,
        1580,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n13 connected endpoint",
    ));
    (graph, 1577, 1581)
}

#[test]
pub(super) fn network_runtime_n13_socket_operations_record_listen_and_connected_flows() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
    for (offset, command) in [
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            sequence: 1,
            note: "n13 bind listening endpoint".to_string(),
        },
        SemanticCommand::ListenSocketEndpoint {
            operation_id: 1583,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            backlog: 16,
            sequence: 2,
            note: "n13 listen endpoint".to_string(),
        },
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1584,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 40000,
            sequence: 1,
            note: "n13 bind connected endpoint".to_string(),
        },
        SemanticCommand::ConnectSocketEndpoint {
            operation_id: 1585,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            remote_addr: [10, 0, 2, 2],
            remote_port: 80,
            sequence: 2,
            note: "n13 connect endpoint".to_string(),
        },
        SemanticCommand::SendSocket {
            operation_id: 1586,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 18,
            sequence: 3,
            note: "n13 send socket".to_string(),
        },
        SemanticCommand::RecvSocket {
            operation_id: 1587,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 19,
            sequence: 4,
            note: "n13 recv socket".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n13-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.socket_operation_count(), 6);
    let listen = graph.socket_operations().iter().find(|operation| operation.id == 1583).unwrap();
    assert_eq!(listen.operation, SocketOperationKind::Listen);
    assert_eq!(listen.local_addr, [10, 0, 2, 15]);
    assert_eq!(listen.local_port, 8080);
    assert_eq!(listen.backlog, 16);
    let send = graph.socket_operations().iter().find(|operation| operation.id == 1586).unwrap();
    assert_eq!(send.operation, SocketOperationKind::Send);
    assert_eq!(send.remote_addr, [10, 0, 2, 2]);
    assert_eq!(send.remote_port, 80);
    assert_eq!(send.byte_len, 18);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("SocketOperationRecorded operation_id=1587 operation=recv")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n13_rejects_invalid_operation_ordering_and_generations() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
    let listen_before_bind = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n13-test",
        SemanticCommand::ListenSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            backlog: 16,
            sequence: 1,
            note: "n13 listen before bind".to_string(),
        },
    ));
    assert_eq!(listen_before_bind.status, CommandStatus::Rejected);
    assert_eq!(
        listen_before_bind.violations,
        vec!["socket listen operation requires bound endpoint".to_string()]
    );

    let stale_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n13-test",
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 2,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            sequence: 1,
            note: "n13 stale endpoint".to_string(),
        },
    ));
    assert_eq!(stale_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        stale_endpoint.violations,
        vec!["socket operation endpoint generation is missing or inactive".to_string()]
    );

    assert!(graph.record_socket_operation_with_id(
        1582,
        listen_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        8080,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n13 bind listening endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1583,
        listen_endpoint,
        1,
        SocketOperationKind::Listen,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        16,
        0,
        2,
        "n13 listen endpoint",
    ));
    let connect_listening = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n13-test",
        SemanticCommand::ConnectSocketEndpoint {
            operation_id: 1584,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            remote_addr: [10, 0, 2, 2],
            remote_port: 80,
            sequence: 3,
            note: "n13 connect listening endpoint".to_string(),
        },
    ));
    assert_eq!(connect_listening.status, CommandStatus::Rejected);
    assert_eq!(
        connect_listening.violations,
        vec!["socket connect operation requires bound non-listening endpoint".to_string()]
    );

    let send_before_connect = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n13-test",
        SemanticCommand::SendSocket {
            operation_id: 1584,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 18,
            sequence: 1,
            note: "n13 send before connect".to_string(),
        },
    ));
    assert_eq!(send_before_connect.status, CommandStatus::Rejected);
    assert_eq!(
        send_before_connect.violations,
        vec!["socket data operation requires connected endpoint".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n13_invariants_reject_socket_operation_sequence_leak() {
    let (mut graph, _, connected_endpoint) = setup_n13_socket_operation_graph();
    assert!(graph.record_socket_operation_with_id(
        1584,
        connected_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        40000,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n13 bind connected endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1585,
        connected_endpoint,
        1,
        SocketOperationKind::Connect,
        [0, 0, 0, 0],
        0,
        [10, 0, 2, 2],
        80,
        0,
        0,
        2,
        "n13 connect endpoint",
    ));
    graph.corrupt_socket_operation_sequence_for_test(1585, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketOperationOrderingInvalid { operation: 1585 })
    );
}
