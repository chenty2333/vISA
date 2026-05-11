use super::*;

pub(in crate::tests) fn setup_b6_virtio_blk_backend_graph() -> (SemanticGraph, DriverStoreBindingId)
{
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:vblk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1790,
        "virtio-blk0",
        "block-device",
        resource,
        resource_generation,
        "virtio-blk-backend-skeleton",
        "virtio-mmio",
        "virtio",
        "virtio-blk",
        "b6 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1791,
        "vblk0",
        1790,
        1,
        512,
        4096,
        false,
        128,
        "b6 block device",
    ));
    let driver_store = graph.register_store(
        "driver.virtio-blk0",
        "driver_virtio_blk.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 1790, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-blk0",
        "device.virtio-blk0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "b6-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1792,
        driver_store,
        driver_store_generation,
        device_ref,
        CapabilityClass::Device,
        "probe",
        handle,
        "b6 device probe capability",
    ));
    assert!(graph.record_driver_store_binding_with_id(
        1793,
        driver_store,
        driver_store_generation,
        1790,
        1,
        1792,
        1,
        "b6 virtio block driver binding",
    ));
    (graph, 1793)
}

#[test]
pub(super) fn block_runtime_b6_virtio_blk_backend_skeleton_binds_driver_and_block_device() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 virtio block backend skeleton".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.virtio_blk_backend_object_count(), 1);
    let backend = &graph.virtio_blk_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1794, 1)
    );
    assert_eq!(backend.block_device, 1791);
    assert_eq!(backend.block_device_generation, 1);
    assert_eq!(backend.driver_binding, binding);
    assert_eq!(backend.driver_binding_generation, 1);
    assert_eq!(backend.device, 1790);
    assert_eq!(backend.device_generation, 1);
    assert_eq!(backend.provider, "substrate_virtio");
    assert_eq!(backend.profile, "virtio-blk-backend-skeleton-v1");
    assert_eq!(backend.model, "virtio-blk");
    assert_eq!(backend.negotiated_features, 64);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VirtioBlkBackendSkeletonBound virtio_blk_backend=1794 block_device=1791@1 driver_binding=1793@1 device=1790@1 queue_size=8 request_queue_index=0 negotiated_features=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b6_rejects_stale_duplicate_and_invalid_virtio_blk_backends() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    let stale_block_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 stale block device".to_string(),
        },
    ));
    assert_eq!(stale_block_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_block_device.violations,
        vec![
            "virtio block backend object block device generation is missing or inactive"
                .to_string()
        ]
    );

    let stale_binding = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 2,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 stale binding".to_string(),
        },
    ));
    assert_eq!(stale_binding.status, CommandStatus::Rejected);
    assert_eq!(
        stale_binding.violations,
        vec![
            "virtio block backend object driver binding generation is missing or inactive"
                .to_string()
        ]
    );

    let bad_provider = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 bad provider".to_string(),
        },
    ));
    assert_eq!(bad_provider.status, CommandStatus::Rejected);
    assert_eq!(
        bad_provider.violations,
        vec!["virtio block backend object provider is unsupported".to_string()]
    );

    let feature_mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 512,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 bad feature negotiation".to_string(),
        },
    ));
    assert_eq!(feature_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        feature_mismatch.violations,
        vec!["virtio block backend negotiated features exceed device features".to_string()]
    );

    let contract_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 8192,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 contract mismatch".to_string(),
        },
    ));
    assert_eq!(contract_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        contract_mismatch.violations,
        vec!["virtio block backend object contract does not match block device".to_string()]
    );

    let invalid_queue_index = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 1,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 invalid queue index".to_string(),
        },
    ));
    assert_eq!(invalid_queue_index.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_queue_index.violations,
        vec!["virtio block backend object contract values are invalid".to_string()]
    );

    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 first backend",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        7,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1795,
            name: "virtio-blk0-backend-dup".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["virtio block backend object already bound to block device generation".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b6_invariants_reject_virtio_blk_generation_and_irq_leaks() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 invariant backend",
    ));
    graph.corrupt_virtio_blk_backend_driver_binding_generation_for_test(1794, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioBlkBackendObjectMissingDriverBinding {
            virtio_blk_backend: 1794,
            driver_binding: 1793,
        })
    ));

    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 invariant backend",
    ));
    graph.corrupt_virtio_blk_backend_irq_vector_for_test(1794, 0);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioBlkBackendObjectInvalid { virtio_blk_backend: 1794 })
    ));

    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 invariant backend",
    ));
    graph.corrupt_virtio_blk_backend_request_queue_index_for_test(1794, 1);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioBlkBackendObjectInvalid { virtio_blk_backend: 1794 })
    ));
}
