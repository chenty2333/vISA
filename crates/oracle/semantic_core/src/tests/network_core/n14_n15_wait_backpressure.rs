use super::*;

pub(in crate::tests) fn setup_n14_socket_wait_graph()
-> (SemanticGraph, EndpointObjectId, EndpointObjectId) {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
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
        "n14 bind listening endpoint",
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
        "n14 listen endpoint",
    ));
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
        "n14 bind connected endpoint",
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
        "n14 connect endpoint",
    ));
    (graph, listen_endpoint, connected_endpoint)
}

#[test]
pub(super) fn network_runtime_n14_socket_wait_resolves_and_cancels_wait_tokens() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let readable_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    let accept_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);

    for (offset, command) in [
        SemanticCommand::CreateWait {
            wait: 1588,
            owner_task: None,
            owner_store: Some(owner_store),
            owner_store_generation: Some(owner_store_generation),
            kind: SemanticWaitKind::SocketReadable,
            generation: 1,
            blockers: vec![readable_blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("recv-would-block".to_string()),
        },
        SemanticCommand::RecordSocketWait {
            socket_wait: 1589,
            wait: 1588,
            wait_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: readable_blocker,
            note: "n14 readable wait".to_string(),
        },
        SemanticCommand::ResolveSocketWait {
            socket_wait: 1589,
            socket_wait_generation: 1,
            ready_sequence: 1,
            byte_len: 19,
            note: "n14 readable ready".to_string(),
        },
        SemanticCommand::CreateWait {
            wait: 1590,
            owner_task: None,
            owner_store: Some(owner_store),
            owner_store_generation: Some(owner_store_generation),
            kind: SemanticWaitKind::SocketAccept,
            generation: 1,
            blockers: vec![accept_blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("accept-would-block".to_string()),
        },
        SemanticCommand::RecordSocketWait {
            socket_wait: 1591,
            wait: 1590,
            wait_generation: 1,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketAccept,
            blocker: accept_blocker,
            note: "n14 accept wait".to_string(),
        },
        SemanticCommand::CancelSocketWait {
            socket_wait: 1591,
            socket_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "n14 close listening socket".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n14-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.socket_wait_count(), 2);
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(graph.wait_records()[1].state, WaitState::Cancelled);
    assert_eq!(graph.socket_waits()[0].state, SocketWaitState::Resolved);
    assert_eq!(graph.socket_waits()[0].ready_sequence, Some(1));
    assert_eq!(graph.socket_waits()[0].byte_len, Some(19));
    assert_eq!(graph.socket_waits()[1].state, SocketWaitState::Cancelled);
    assert_eq!(graph.socket_waits()[1].cancel_reason, Some(WaitCancelReason::CloseFd));
    assert!(
        graph.event_log_tail(1)[0].kind.summary().contains("SocketWaitCancelled socket_wait=1591")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n14_accept_wait_can_resolve_without_payload_bytes() {
    let (mut graph, listen_endpoint, _) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let accept_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);

    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1592,
                owner_task: None,
                owner_store: Some(owner_store),
                owner_store_generation: Some(owner_store_generation),
                kind: SemanticWaitKind::SocketAccept,
                generation: 1,
                blockers: vec![accept_blocker],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("accept-ready".to_string()),
            })
            .is_ok()
    );
    assert!(
        graph
            .apply(SemanticCommand::RecordSocketWait {
                socket_wait: 1593,
                wait: 1592,
                wait_generation: 1,
                endpoint: listen_endpoint,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketAccept,
                blocker: accept_blocker,
                note: "socket accept wait".to_string(),
            })
            .is_ok()
    );
    assert!(
        graph
            .apply(SemanticCommand::ResolveSocketWait {
                socket_wait: 1593,
                socket_wait_generation: 1,
                ready_sequence: 1,
                byte_len: 0,
                note: "accept ready without payload".to_string(),
            })
            .is_ok()
    );

    let socket_wait = graph.socket_waits().iter().find(|record| record.id == 1593).unwrap();
    assert_eq!(socket_wait.state, SocketWaitState::Resolved);
    assert_eq!(socket_wait.byte_len, Some(0));
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n14_rejects_wrong_socket_wait_state_and_generation() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let listen_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);
    let connected_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1588,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![listen_blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let wrong_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n14-test",
        SemanticCommand::RecordSocketWait {
            socket_wait: 1589,
            wait: 1588,
            wait_generation: 1,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: listen_blocker,
            note: "n14 readable wait on listening endpoint".to_string(),
        },
    ));
    assert_eq!(wrong_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_endpoint.violations,
        vec!["socket data wait requires connected endpoint".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1590,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![connected_blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let stale_endpoint = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n14-test",
        SemanticCommand::RecordSocketWait {
            socket_wait: 1591,
            wait: 1590,
            wait_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 2,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: ContractObjectRef::new(
                ContractObjectKind::EndpointObject,
                connected_endpoint,
                2,
            ),
            note: "n14 stale endpoint wait".to_string(),
        },
    ));
    assert_eq!(stale_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        stale_endpoint.violations,
        vec!["socket wait token does not reference the requested endpoint blocker".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n14_invariants_reject_socket_wait_endpoint_generation_leak() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1588,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_socket_wait_with_id(
        1589,
        1588,
        1,
        connected_endpoint,
        1,
        SemanticWaitKind::SocketReadable,
        blocker,
        "n14 readable wait",
    ));
    graph.corrupt_socket_wait_endpoint_generation_for_test(1589, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketWaitMissingEndpoint {
            socket_wait: 1589,
            endpoint: connected_endpoint,
        })
    );
}

#[test]
pub(super) fn network_runtime_n15_backpressure_records_throttle_reject_and_drop_policy() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();

    for (offset, command) in [
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueHighWatermark,
            action: NetworkBackpressureAction::ThrottleProducer,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 rx high watermark throttle".to_string(),
        },
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1595,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 2,
            note: "n15 tx reject send at queue limit".to_string(),
        },
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1596,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 1,
            dropped_bytes: 1514,
            sequence: 3,
            note: "n15 rx drop newest when full".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n15-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.network_backpressure_count(), 3);
    let reject = graph.network_backpressures().iter().find(|record| record.id == 1595).unwrap();
    assert_eq!(
        reject.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkBackpressure, 1595, 1)
    );
    assert_eq!(reject.endpoint, Some(connected_endpoint));
    assert_eq!(reject.socket, Some(1580));
    assert_eq!(reject.owner_store, graph.store_id("linux_socket_service"));
    assert_eq!(reject.action, NetworkBackpressureAction::RejectSend);
    assert_eq!(reject.dropped_packets, 0);
    let drop_record =
        graph.network_backpressures().iter().find(|record| record.id == 1596).unwrap();
    assert_eq!(drop_record.action, NetworkBackpressureAction::DropNewest);
    assert_eq!(drop_record.dropped_bytes, 1514);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkBackpressureRecorded backpressure=1596")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n15_rejects_stale_queue_missing_endpoint_and_bad_drop_evidence() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 2,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueHighWatermark,
            action: NetworkBackpressureAction::ThrottleProducer,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 stale rx queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network backpressure packet queue generation is missing or inactive".to_string()]
    );

    let missing_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 reject without endpoint".to_string(),
        },
    ));
    assert_eq!(missing_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        missing_endpoint.violations,
        vec!["network backpressure reject-send requires endpoint attribution".to_string()]
    );

    let bad_drop = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 1514,
            sequence: 1,
            note: "n15 bad drop counters".to_string(),
        },
    ));
    assert_eq!(bad_drop.status, CommandStatus::Rejected);
    assert_eq!(
        bad_drop.violations,
        vec!["network backpressure drop action requires dropped packet evidence".to_string()]
    );

    assert!(graph.record_network_backpressure_with_id(
        1594,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        Some(connected_endpoint),
        Some(1),
        PacketBufferDirection::Tx,
        NetworkBackpressureReason::QueueFull,
        NetworkBackpressureAction::RejectSend,
        4,
        4,
        0,
        0,
        7,
        "n15 first tx reject",
    ));
    let duplicate_sequence = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1595,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 7,
            note: "n15 duplicate sequence".to_string(),
        },
    ));
    assert_eq!(duplicate_sequence.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_sequence.violations,
        vec!["network backpressure sequence already exists for queue direction".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n15_invariants_reject_packet_queue_generation_leak() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_backpressure_with_id(
        1594,
        1575,
        1,
        1541,
        1,
        1544,
        1,
        None,
        None,
        PacketBufferDirection::Rx,
        NetworkBackpressureReason::QueueHighWatermark,
        NetworkBackpressureAction::ThrottleProducer,
        4,
        4,
        0,
        0,
        1,
        "n15 rx high watermark throttle",
    ));
    graph.corrupt_network_backpressure_queue_generation_for_test(1594, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkBackpressureMissingQueue {
            backpressure: 1594,
            packet_queue: 1544,
        })
    );
}
