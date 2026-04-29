use super::*;

#[test]
fn semantic_roots_reject_packet_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_device_object_count = 1;
    package.semantic.packet_device_objects.push(artifact_manifest::PacketDeviceObjectManifest {
        id: 31,
        name: "net0".to_owned(),
        device: 17,
        device_generation: 1,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 67,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_buffer_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_buffer_object_count = 1;
    package.semantic.packet_buffer_objects.push(artifact_manifest::PacketBufferObjectManifest {
        id: 32,
        packet_device: 31,
        packet_device_generation: 1,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 1,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 68,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet buffer object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_queue_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_queue_object_count = 1;
    package.semantic.packet_queue_objects.push(artifact_manifest::PacketQueueObjectManifest {
        id: 33,
        name: "rx0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 69,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet queue object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_descriptor_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_descriptor_object_count = 1;
    package.semantic.packet_descriptors.push(artifact_manifest::PacketDescriptorObjectManifest {
        id: 34,
        packet_queue: 33,
        packet_queue_generation: 1,
        packet_buffer: 31,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 70,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet descriptor object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fake_net_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fake_net_backend_object_count = 1;
    package.semantic.fake_net_backends.push(artifact_manifest::FakeNetBackendObjectManifest {
        id: 35,
        name: "fake-net0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-net-v1".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        frame_format_version: 2,
        max_payload_len: 512,
        deterministic_seed: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 71,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fake net backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fake_block_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fake_block_backend_object_count = 1;
    package.semantic.fake_block_backends.push(artifact_manifest::FakeBlockBackendObjectManifest {
        id: 56,
        name: "fake-block0".to_owned(),
        block_device: 51,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 72,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fake block backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_virtio_net_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.virtio_net_backend_object_count = 1;
    package.semantic.virtio_net_backends.push(artifact_manifest::VirtioNetBackendObjectManifest {
        id: 36,
        name: "virtio-net0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        driver_binding: 1202,
        driver_binding_generation: 1,
        device: 30,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-net-backend-skeleton-v1".to_owned(),
        model: "virtio-net".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        frame_format_version: 2,
        max_payload_len: 512,
        device_features: 0x1,
        driver_features: 0x1,
        negotiated_features: 0x1,
        rx_queue_index: 0,
        tx_queue_index: 1,
        queue_size: 4,
        irq_vector: 5,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 72,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "virtio net backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_virtio_blk_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.virtio_blk_backend_object_count = 1;
    package.semantic.virtio_blk_backends.push(artifact_manifest::VirtioBlkBackendObjectManifest {
        id: 37,
        name: "virtio-blk0".to_owned(),
        block_device: 32,
        block_device_generation: 1,
        driver_binding: 1203,
        driver_binding_generation: 1,
        device: 30,
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
        recorded_at_event: 73,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "virtio block backend object root/count mismatch");
}
