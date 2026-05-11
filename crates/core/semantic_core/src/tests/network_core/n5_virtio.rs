use super::*;

pub(in crate::tests) fn setup_n5_virtio_net_backend_graph() -> (SemanticGraph, DriverStoreBindingId)
{
    let mut graph = setup_n3_packet_descriptor_graph();
    let driver_store = graph.register_store(
        "driver.virtio-net2",
        "driver_virtio_net.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 1540, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "device.virtio-net2",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "n5-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1551,
        driver_store,
        driver_store_generation,
        device_ref,
        CapabilityClass::Device,
        "probe",
        handle,
        "n5 device probe capability",
    ));
    assert!(graph.record_driver_store_binding_with_id(
        1552,
        driver_store,
        driver_store_generation,
        1540,
        1,
        1551,
        1,
        "n5 virtio net driver binding",
    ));
    (graph, 1552)
}

#[test]
pub(super) fn network_runtime_n5_virtio_net_backend_skeleton_binds_driver_and_packet_device() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 virtio backend skeleton".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.virtio_net_backend_object_count(), 1);
    let backend = &graph.virtio_net_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1)
    );
    assert_eq!(backend.packet_device, 1541);
    assert_eq!(backend.packet_device_generation, 1);
    assert_eq!(backend.driver_binding, binding);
    assert_eq!(backend.driver_binding_generation, 1);
    assert_eq!(backend.device, 1540);
    assert_eq!(backend.device_generation, 1);
    assert_eq!(backend.provider, "substrate_virtio");
    assert_eq!(backend.profile, "virtio-net-backend-skeleton-v1");
    assert_eq!(backend.model, "virtio-net");
    assert_eq!(backend.negotiated_features, 32);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VirtioNetBackendSkeletonBound virtio_net_backend=1553 packet_device=1541@1 driver_binding=1552@1 device=1540@1 queue_size=4 rx_queue_index=0 tx_queue_index=1 negotiated_features=32 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n5_rejects_stale_mismatched_or_unsupported_backend() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    let stale_packet_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale_packet_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_device.violations,
        vec![
            "virtio net backend object packet device generation is missing or inactive".to_string()
        ]
    );

    let stale_binding = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 2,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 stale driver binding".to_string(),
        },
    ));
    assert_eq!(stale_binding.status, CommandStatus::Rejected);
    assert_eq!(
        stale_binding.violations,
        vec![
            "virtio net backend object driver binding generation is missing or inactive"
                .to_string()
        ]
    );

    let bad_provider = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 bad provider".to_string(),
        },
    ));
    assert_eq!(bad_provider.status, CommandStatus::Rejected);
    assert_eq!(
        bad_provider.violations,
        vec!["virtio net backend object provider is unsupported".to_string()]
    );

    let feature_mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 64,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 bad feature negotiation".to_string(),
        },
    ));
    assert_eq!(feature_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        feature_mismatch.violations,
        vec!["virtio net backend negotiated features exceed device features".to_string()]
    );

    let contract_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1400,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 contract mismatch".to_string(),
        },
    ));
    assert_eq!(contract_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        contract_mismatch.violations,
        vec!["virtio net backend object contract does not match packet device".to_string()]
    );

    let invalid_irq = graph.apply_envelope(CommandEnvelope::new(
        6,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 0,
            note: "n5 invalid irq vector".to_string(),
        },
    ));
    assert_eq!(invalid_irq.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_irq.violations,
        vec!["virtio net backend object contract values are invalid".to_string()]
    );

    let invalid_queue_indices = graph.apply_envelope(CommandEnvelope::new(
        7,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 2,
            tx_queue_index: 3,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 invalid queue indices".to_string(),
        },
    ));
    assert_eq!(invalid_queue_indices.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_queue_indices.violations,
        vec!["virtio net backend object contract values are invalid".to_string()]
    );

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
        "n5 first backend",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        8,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1554,
            name: "virtio-net2-backend-dup".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["virtio net backend object already bound to packet device generation".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n5_invariants_reject_virtio_backend_generation_leak() {
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
        "n5 invariant backend",
    ));
    graph.corrupt_virtio_net_backend_driver_binding_generation_for_test(1553, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioNetBackendObjectMissingDriverBinding {
            virtio_net_backend: 1553,
            driver_binding: 1552,
        })
    ));
}

#[test]
pub(super) fn network_runtime_n5_invariants_reject_invalid_virtio_irq_vector() {
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
        "n5 invariant backend",
    ));
    graph.corrupt_virtio_net_backend_irq_vector_for_test(1553, 0);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioNetBackendObjectInvalid { virtio_net_backend: 1553 })
    ));
}

#[test]
pub(super) fn network_runtime_n5_invariants_reject_noncanonical_queue_indices() {
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
        "n5 invariant backend",
    ));
    graph.corrupt_virtio_net_backend_queue_indices_for_test(1553, 2, 3);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioNetBackendObjectInvalid { virtio_net_backend: 1553 })
    ));
}
