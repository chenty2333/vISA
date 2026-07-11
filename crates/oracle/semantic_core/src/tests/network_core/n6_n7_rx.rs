use super::*;

pub(in crate::tests) fn setup_n6_network_rx_interrupt_graph() -> SemanticGraph {
    setup_n6_network_rx_interrupt_graph_with_irq_capability(true)
}

pub(in crate::tests) fn setup_n6_network_rx_interrupt_graph_with_irq_capability(
    grant_irq_capability: bool,
) -> SemanticGraph {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    assert!(graph.record_virtio_net_backend_object_with_id(
        1553,
        "virtio-net2-backend",
        1541,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-net-backend-skeleton-v1",
        "virtio-net",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        32,
        32,
        32,
        0,
        1,
        4,
        5,
        "n6 backend",
    ));
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:virtio-net2-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == binding).cloned().unwrap();
    assert!(graph.record_irq_line_object_with_id(
        1554,
        1540,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "n6 rx irq line",
    ));
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 1554, 1);
    if grant_irq_capability {
        let irq_cap = graph.grant_capability_with_authority_ref(
            "driver.virtio-net2",
            "irq.virtio-net2.rx",
            AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
            &["ack"],
            "store",
            "n6-test",
            true,
        );
        let irq_handle = graph
            .capabilities()
            .record(irq_cap)
            .and_then(|record| record.store_local_handle(vec!["ack".to_string()]))
            .unwrap();
        assert!(graph.record_device_capability_with_id(
            1560,
            binding_record.driver_store,
            binding_record.driver_store_generation,
            irq_ref,
            CapabilityClass::IrqLine,
            "ack",
            irq_handle,
            "n6 irq ack capability",
        ));
    }
    assert!(graph.record_irq_event_with_id(
        1555,
        1554,
        1,
        1540,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1,
        "n6 rx irq event",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n6_rx_interrupt_records_irq_to_rx_queue_path() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 rx interrupt path".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_rx_interrupt_count(), 1);
    let rx_interrupt = &graph.network_rx_interrupts()[0];
    assert_eq!(
        rx_interrupt.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRxInterrupt, 1556, 1)
    );
    assert_eq!(rx_interrupt.virtio_net_backend, 1553);
    assert_eq!(rx_interrupt.irq_event, 1555);
    assert_eq!(rx_interrupt.packet_device, 1541);
    assert_eq!(rx_interrupt.rx_queue, 1544);
    assert_eq!(rx_interrupt.ready_descriptors, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "NetworkRxInterruptRecorded rx_interrupt=1556 virtio_net_backend=1553@1 irq_event=1555@1 packet_device=1541@1 rx_queue=1544@1 ready_descriptors=1 sequence=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n6_rejects_stale_wrong_queue_overdepth_and_duplicate_irq() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let stale_irq = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 stale irq".to_string(),
        },
    ));
    assert_eq!(stale_irq.status, CommandStatus::Rejected);
    assert_eq!(
        stale_irq.violations,
        vec!["network rx interrupt irq event generation is missing or inactive".to_string()]
    );

    let tx_queue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1545,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 tx queue is not rx".to_string(),
        },
    ));
    assert_eq!(tx_queue.status, CommandStatus::Rejected);
    assert_eq!(
        tx_queue.violations,
        vec!["network rx interrupt rx queue does not match backend packet device".to_string()]
    );

    let overdepth = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 5,
            sequence: 1,
            note: "n6 overdepth".to_string(),
        },
    ));
    assert_eq!(overdepth.status, CommandStatus::Rejected);
    assert_eq!(
        overdepth.violations,
        vec!["network rx interrupt ready descriptors exceed rx queue depth".to_string()]
    );

    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n6 first rx interrupt",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1557,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 2,
            note: "n6 duplicate irq event".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network rx interrupt already recorded for irq event generation".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n6_rejects_missing_irq_ack_capability() {
    let mut graph = setup_n6_network_rx_interrupt_graph_with_irq_capability(false);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 missing irq ack capability".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert_eq!(
        result.violations,
        vec!["network rx interrupt irq ack capability is missing".to_string()]
    );
    assert_eq!(graph.network_rx_interrupt_count(), 0);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n6_invariants_reject_rx_queue_generation_leak() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n6 invariant rx interrupt",
    ));
    graph.corrupt_network_rx_interrupt_queue_generation_for_test(1556, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkRxInterruptMissingRxQueue {
            rx_interrupt: 1556,
            rx_queue: 1544,
        })
    ));
}

pub(in crate::tests) fn setup_n7_network_rx_wait_graph() -> SemanticGraph {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n7 rx interrupt",
    ));
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1544, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1561,
                owner_task: None,
                owner_store: Some(binding_record.driver_store),
                owner_store_generation: Some(binding_record.driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![rx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.virtio-net2:rx-queue".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1562,
        1561,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        rx_queue_ref,
        "n7 pending rx queue io wait",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n7_rx_interrupt_resolves_rx_queue_wait() {
    let mut graph = setup_n7_network_rx_wait_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1562,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 1,
            note: "n7 rx wait resolves from interrupt".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_rx_wait_resolution_count(), 1);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Resolved);
    assert_eq!(graph.io_waits()[0].completion_irq_event, Some(1555));
    let wait = graph.wait_records().iter().find(|record| record.id == 1561).unwrap();
    assert_eq!(wait.state, WaitState::Resolved);
    let resolution = &graph.network_rx_wait_resolutions()[0];
    assert_eq!(
        resolution.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRxWaitResolution, 1563, 1)
    );
    assert_eq!(resolution.rx_interrupt, 1556);
    assert_eq!(resolution.rx_queue, 1544);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "NetworkRxWaitResolved resolution=1563 io_wait=1562@1 wait=1561@1 rx_interrupt=1556@1 rx_queue=1544@1 ready_descriptors=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n7_rejects_stale_interrupt_and_wrong_wait_blocker() {
    let mut graph = setup_n7_network_rx_wait_graph();
    let stale_interrupt = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1562,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 2,
            note: "n7 stale interrupt".to_string(),
        },
    ));
    assert_eq!(stale_interrupt.status, CommandStatus::Rejected);
    assert_eq!(
        stale_interrupt.violations,
        vec!["network rx wait interrupt generation is missing or inactive".to_string()]
    );

    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let tx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1545, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1564,
                owner_task: None,
                owner_store: Some(binding_record.driver_store),
                owner_store_generation: Some(binding_record.driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![tx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.virtio-net2:tx-queue".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1565,
        1564,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        tx_queue_ref,
        "n7 wrong tx queue io wait",
    ));
    let wrong_blocker = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1565,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 1,
            note: "n7 tx queue must not resolve rx wait".to_string(),
        },
    ));
    assert_eq!(wrong_blocker.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_blocker.violations,
        vec!["network rx wait blocker must be the rx packet queue".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n7_invariants_reject_resolution_queue_generation_leak() {
    let mut graph = setup_n7_network_rx_wait_graph();
    assert!(graph.resolve_network_rx_wait_with_id(1563, 1562, 1, 1556, 1, "n7 resolved rx wait",));
    graph.corrupt_network_rx_wait_resolution_queue_generation_for_test(1563, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkRxWaitResolutionMissingRxQueue {
            resolution: 1563,
            rx_queue: 1544,
        })
    );
}
