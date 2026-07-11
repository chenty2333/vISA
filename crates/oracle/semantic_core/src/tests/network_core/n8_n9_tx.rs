use super::*;

pub(in crate::tests) fn setup_n8_network_tx_gate_graph() -> (SemanticGraph, CapabilityHandle) {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    assert!(graph.record_packet_descriptor_object_with_id(
        1547,
        1545,
        1,
        1543,
        1,
        0,
        64,
        "n8 tx packet descriptor",
    ));
    let packet_device_ref = ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1541, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "packet-device.net2",
        AuthorityObjectRef::internal(CapabilityClass::PacketDevice, packet_device_ref),
        &["tx"],
        "store",
        "n8-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1570,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        packet_device_ref,
        CapabilityClass::PacketDevice,
        "tx",
        handle.clone(),
        "n8 packet tx capability",
    ));
    (graph, handle)
}

#[test]
pub(super) fn network_runtime_n8_tx_descriptor_requires_packet_device_capability() {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1571,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle,
            note: "n8 tx gate allowed".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_tx_capability_gate_count(), 1);
    let gate = &graph.network_tx_capability_gates()[0];
    assert_eq!(
        gate.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkTxCapabilityGate, 1571, 1)
    );
    assert_eq!(gate.packet_device, 1541);
    assert_eq!(gate.tx_queue, 1545);
    assert_eq!(gate.packet_descriptor, 1547);
    assert_eq!(gate.operation, "tx");
    assert_eq!(gate.byte_len, 64);
    assert_eq!(gate.sequence, 2);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkTxCapabilityGateRecorded tx_gate=1571")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n8_rejects_forged_handle_and_rx_descriptor() {
    let (mut graph, mut forged_handle) = setup_n8_network_tx_gate_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    forged_handle.generation += 1;
    let forged = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1571,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: forged_handle,
            note: "n8 forged tx handle".to_string(),
        },
    ));
    assert_eq!(forged.status, CommandStatus::Rejected);
    assert_eq!(forged.violations, vec!["network tx capability gate handle mismatch".to_string()]);
    assert_eq!(graph.network_tx_capability_gate_count(), 0);

    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n8 rx descriptor must not tx",
    ));
    let valid_handle = graph
        .capabilities()
        .record(
            graph.device_capabilities().iter().find(|record| record.id == 1570).unwrap().capability,
        )
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    let wrong_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1572,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1546,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: valid_handle,
            note: "n8 rx descriptor rejected by tx gate".to_string(),
        },
    ));
    assert_eq!(wrong_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_descriptor.violations,
        vec!["network tx capability gate requires tx packet queue".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n8_invariants_reject_capability_generation_leak() {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    assert!(graph.record_network_tx_capability_gate_with_id(
        1571,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1547,
        1,
        1570,
        1,
        handle,
        "n8 tx gate allowed",
    ));
    graph.corrupt_network_tx_gate_capability_generation_for_test(1571, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid { tx_gate: 1571 })
    );
}

pub(in crate::tests) fn setup_n9_network_tx_completion_graph() -> SemanticGraph {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    assert!(graph.record_network_tx_capability_gate_with_id(
        1571,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1547,
        1,
        1570,
        1,
        handle,
        "n9 tx gate allowed",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n9_tx_completion_follows_allowed_gate() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 1,
            note: "n9 tx completion path".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_tx_completion_count(), 1);
    let completion = &graph.network_tx_completions()[0];
    assert_eq!(
        completion.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkTxCompletion, 1572, 1)
    );
    assert_eq!(completion.tx_gate, 1571);
    assert_eq!(completion.backend, backend);
    assert_eq!(completion.packet_device, 1541);
    assert_eq!(completion.tx_queue, 1545);
    assert_eq!(completion.packet_descriptor, 1547);
    assert_eq!(completion.packet_buffer, 1543);
    assert_eq!(completion.byte_len, 64);
    assert_eq!(completion.sequence, 2);
    assert_eq!(completion.completion_sequence, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "NetworkTxCompleted completion=1572 tx_gate=1571@1 backend=virtio-net-backend-object:1553@1 driver_store={}@{} packet_device=1541@1 tx_queue=1545@1 packet_descriptor=1547@1 packet_buffer=1543@1 byte_len=64 sequence=2 completion_sequence=1 generation=1",
            completion.driver_store, completion.driver_store_generation
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n9_rejects_stale_gate_wrong_backend_and_duplicate_completion() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let stale_gate = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 2,
            backend,
            completion_sequence: 1,
            note: "n9 stale gate".to_string(),
        },
    ));
    assert_eq!(stale_gate.status, CommandStatus::Rejected);
    assert_eq!(
        stale_gate.violations,
        vec!["network tx completion gate generation is missing or inactive".to_string()]
    );

    let wrong_backend = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1541, 1),
            completion_sequence: 1,
            note: "n9 wrong backend".to_string(),
        },
    ));
    assert_eq!(wrong_backend.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_backend.violations,
        vec!["network tx completion backend generation is missing or inactive".to_string()]
    );

    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 tx completion",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1573,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 2,
            note: "n9 duplicate gate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network tx completion gate already completed".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n9_invariants_reject_completion_generation_leak() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 tx completion",
    ));
    graph.corrupt_network_tx_completion_gate_generation_for_test(1572, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkTxCompletionMissingGate {
            completion: 1572,
            tx_gate: 1571,
        })
    );
}

#[test]
pub(super) fn network_runtime_n9_invariants_reject_duplicate_completion_sequence() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let handle = graph
        .device_capabilities()
        .iter()
        .find(|record| record.id == 1570)
        .and_then(|record| graph.capabilities().record(record.capability))
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    assert!(graph.record_packet_buffer_object_with_id(
        1548,
        1541,
        1,
        PacketBufferDirection::Tx,
        2,
        512,
        32,
        3,
        PacketBufferObjectState::Filled,
        "n9 second tx packet buffer",
    ));
    assert!(graph.record_packet_descriptor_object_with_id(
        1549,
        1545,
        1,
        1548,
        1,
        1,
        32,
        "n9 second tx packet descriptor",
    ));
    assert!(graph.record_network_tx_capability_gate_with_id(
        1573,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1549,
        1,
        1570,
        1,
        handle,
        "n9 second tx gate allowed",
    ));
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 first tx completion",
    ));
    assert!(graph.record_network_tx_completion_with_id(
        1574,
        1573,
        1,
        backend,
        2,
        "n9 second tx completion",
    ));
    graph.corrupt_network_tx_completion_sequence_for_test(1574, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkTxCompletionDuplicateSequence {
            completion: 1574,
            tx_queue: 1545,
            completion_sequence: 1,
        })
    );
}
