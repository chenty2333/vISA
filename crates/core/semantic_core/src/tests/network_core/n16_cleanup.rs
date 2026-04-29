use super::*;

#[test]
pub(super) fn network_runtime_n16_driver_cleanup_cancels_socket_waits_and_revokes_packet_capability()
 {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n16-test",
                SemanticCommand::CreateWait {
                    wait: 1597,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("n16 pending recv before driver fault".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                2,
                "n16-test",
                SemanticCommand::RecordSocketWait {
                    socket_wait: 1598,
                    wait: 1597,
                    wait_generation: 1,
                    endpoint: connected_endpoint,
                    endpoint_generation: 1,
                    wait_kind: SemanticWaitKind::SocketReadable,
                    blocker,
                    note: "n16 pending socket wait before driver fault".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );

    let result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 network driver cleanup".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_driver_cleanup_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
    let cleanup = &graph.network_driver_cleanups()[0];
    assert_eq!(
        cleanup.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkDriverCleanup, 1599, 1)
    );
    assert_eq!(cleanup.state, NetworkDriverCleanupState::Completed);
    assert_eq!(cleanup.io_cleanup, 1600);
    assert_eq!(cleanup.cancelled_socket_waits.len(), 1);
    assert_eq!(
        cleanup.cancelled_socket_waits[0],
        ContractObjectRef::new(ContractObjectKind::SocketWait, 1598, 1)
    );
    assert_eq!(
        cleanup.cancelled_wait_tokens[0],
        ContractObjectRef::new(ContractObjectKind::WaitToken, 1597, 1)
    );
    assert_eq!(
        cleanup.revoked_packet_capabilities,
        vec![ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1570, 1)]
    );
    let socket_wait = graph.socket_waits().iter().find(|record| record.id == 1598).unwrap();
    assert_eq!(socket_wait.state, SocketWaitState::Cancelled);
    assert_eq!(socket_wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(
        graph.wait_records().iter().find(|record| record.id == 1597).unwrap().state,
        WaitState::Cancelled
    );
    assert_eq!(
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).unwrap().state,
        DriverStoreBindingState::Released
    );
    assert_eq!(
        graph.device_capabilities().iter().find(|record| record.id == 1570).unwrap().state,
        DeviceCapabilityState::Revoked
    );
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkDriverCleanupCompleted cleanup=1599")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n16_rejects_stale_adapter_wrong_backend_and_duplicate_io_cleanup() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();

    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["network driver cleanup adapter generation is missing or inactive".to_string()]
    );

    let wrong_backend = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1551, 1),
            reason: "device-fault".to_string(),
            note: "n16 wrong backend".to_string(),
        },
    ));
    assert_eq!(wrong_backend.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_backend.violations,
        vec!["network driver cleanup adapter does not match packet device/backend".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n16-test",
                SemanticCommand::CleanupNetworkDriver {
                    cleanup: 1599,
                    io_cleanup: 1600,
                    adapter: 1575,
                    adapter_generation: 1,
                    packet_device: 1541,
                    packet_device_generation: 1,
                    backend: ContractObjectRef::new(
                        ContractObjectKind::VirtioNetBackendObject,
                        1553,
                        1
                    ),
                    reason: "device-fault".to_string(),
                    note: "n16 first cleanup".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1601,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 duplicate io cleanup".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network driver cleanup backend driver binding is missing or inactive".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n16_invariants_reject_stale_cleanup_effect_generation() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    assert!(graph.cleanup_network_driver_with_id(
        1599,
        1600,
        1575,
        1,
        1541,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        "device-fault",
        "n16 network driver cleanup",
    ));
    graph.corrupt_network_driver_cleanup_revoked_capability_generation_for_test(1599, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkDriverCleanupMissingEffectTarget {
            cleanup: 1599,
            target: ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1570, 2),
        })
    );
}
