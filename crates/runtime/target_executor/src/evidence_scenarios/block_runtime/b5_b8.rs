use super::*;

pub(crate) fn record_block_runtime_b5_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let bind_backend = semantic.apply_envelope(CommandEnvelope::new(
        222,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_026,
            name: "fake-block0".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-bind-fake-block-backend".to_owned(),
        },
    ));
    if bind_backend.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b5 bind fake backend command {} ({}) failed: status={} violations={:?}",
            bind_backend.command_id,
            bind_backend.command,
            bind_backend.status.as_str(),
            bind_backend.violations
        )
        .into());
    }

    let duplicate_backend = semantic.apply_envelope(CommandEnvelope::new(
        223,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_027,
            name: "fake-block0-duplicate".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-duplicate-fake-block-backend".to_owned(),
        },
    ));
    if duplicate_backend.status != CommandStatus::Rejected
        || !duplicate_backend.violations.iter().any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "block runtime b5 duplicate fake backend command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_backend.command_id,
            duplicate_backend.command,
            duplicate_backend.status.as_str(),
            duplicate_backend.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        224,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_028,
            name: "fake-block0-stale".to_owned(),
            block_device: 20_002,
            block_device_generation: 2,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend.violations.iter().any(|violation| {
            violation.contains("block device generation") || violation.contains("missing")
        })
    {
        return Err(format!(
            "block runtime b5 stale fake backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let mismatched_backend = semantic.apply_envelope(CommandEnvelope::new(
        225,
        "target-executor-b5",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 20_029,
            name: "fake-block0-mismatched".to_owned(),
            block_device: 20_002,
            block_device_generation: 1,
            provider: FAKE_BLOCK_BACKEND_PROVIDER.to_owned(),
            profile: FAKE_BLOCK_BACKEND_PROFILE.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count.saturating_add(1),
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            deterministic_seed: config.deterministic_seed,
            note: "b5-reject-contract-mismatch".to_owned(),
        },
    ));
    if mismatched_backend.status != CommandStatus::Rejected
        || !mismatched_backend
            .violations
            .iter()
            .any(|violation| violation.contains("contract does not match"))
    {
        return Err(format!(
            "block runtime b5 mismatched fake backend command {} ({}) was not rejected: status={} violations={:?}",
            mismatched_backend.command_id,
            mismatched_backend.command,
            mismatched_backend.status.as_str(),
            mismatched_backend.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b6_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let config = VirtioBlkBackendConfig::blk0();
    let block_resource =
        semantic.register_resource(ResourceKind::BlockDevice, None, "block-device:virtio-blk0");
    let block_resource_generation = semantic
        .resource_handle(block_resource)
        .map(|handle| handle.generation)
        .ok_or("b6 virtio block device resource handle is missing")?;
    if !semantic.record_device_object_with_id(
        20_030,
        "virtio-blk0",
        "block-device",
        block_resource,
        block_resource_generation,
        "virtio-blk-backend-skeleton",
        "virtio-mmio",
        "virtio",
        VIRTIO_BLK_BACKEND_MODEL,
        "b6-record-virtio-block-backing-device",
    ) {
        return Err("b6 virtio block backing device could not be recorded".into());
    }

    let block_device = semantic.apply_envelope(CommandEnvelope::new(
        226,
        "target-executor-b6",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_031,
            name: "vblk0".to_owned(),
            device: 20_030,
            device_generation: 1,
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            note: "b6-record-virtio-block-device-object".to_owned(),
        },
    ));
    if block_device.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b6 block device command {} ({}) failed: status={} violations={:?}",
            block_device.command_id,
            block_device.command,
            block_device.status.as_str(),
            block_device.violations
        )
        .into());
    }

    let block_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for b6 evidence")?;
    let block_driver_store_generation = semantic
        .store_handle(block_driver_store)
        .map(|handle| handle.generation)
        .ok_or("b6 block driver store handle is missing")?;
    let virtio_device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 20_030, 1);
    let virtio_device_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "device.virtio-blk0",
        AuthorityObjectRef::internal(CapabilityClass::Device, virtio_device_ref),
        &["probe"],
        "store",
        "b6-virtio-blk-device-capability",
        true,
    );
    let virtio_device_handle = semantic
        .capabilities()
        .record(virtio_device_capability)
        .and_then(|record| record.store_local_handle(vec!["probe".to_owned()]))
        .ok_or("b6 virtio block device capability handle is missing")?;

    let commands = [
        CommandEnvelope::new(
            227,
            "target-executor-b6",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 20_032,
                driver_store: block_driver_store,
                driver_store_generation: block_driver_store_generation,
                target: virtio_device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: virtio_device_handle,
                note: "b6-record-virtio-block-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            228,
            "target-executor-b6",
            SemanticCommand::BindDriverStore {
                binding: 20_033,
                driver_store: block_driver_store,
                driver_store_generation: block_driver_store_generation,
                device: 20_030,
                device_generation: 1,
                device_capability: 20_032,
                device_capability_generation: 1,
                note: "b6-bind-virtio-block-driver-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            229,
            "target-executor-b6",
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend: 20_034,
                name: "virtio-blk0-backend".to_owned(),
                block_device: 20_031,
                block_device_generation: 1,
                driver_binding: 20_033,
                driver_binding_generation: 1,
                provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
                profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
                model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
                sector_size: config.sector_size,
                sector_count: config.sector_count,
                read_only: config.read_only,
                max_transfer_sectors: config.max_transfer_sectors,
                device_features: config.device_features,
                driver_features: config.driver_features,
                negotiated_features: config.negotiated_features,
                request_queue_index: config.request_queue_index,
                queue_size: config.queue_size,
                irq_vector: config.irq_vector,
                note: "b6-bind-virtio-block-backend-skeleton-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b6 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let duplicate_backend = semantic.apply_envelope(CommandEnvelope::new(
        230,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_035,
            name: "virtio-blk0-backend-duplicate".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-duplicate-virtio-block-backend".to_owned(),
        },
    ));
    if duplicate_backend.status != CommandStatus::Rejected
        || !duplicate_backend.violations.iter().any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "block runtime b6 duplicate backend command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_backend.command_id,
            duplicate_backend.command,
            duplicate_backend.status.as_str(),
            duplicate_backend.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        231,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_036,
            name: "virtio-blk0-backend-stale".to_owned(),
            block_device: 20_031,
            block_device_generation: 2,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend.violations.iter().any(|violation| {
            violation.contains("block device generation") || violation.contains("missing")
        })
    {
        return Err(format!(
            "block runtime b6 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let stale_binding = semantic.apply_envelope(CommandEnvelope::new(
        232,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_037,
            name: "virtio-blk0-backend-stale-binding".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 2,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.negotiated_features,
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-stale-driver-binding-generation".to_owned(),
        },
    ));
    if stale_binding.status != CommandStatus::Rejected
        || !stale_binding
            .violations
            .iter()
            .any(|violation| violation.contains("driver binding generation"))
    {
        return Err(format!(
            "block runtime b6 stale binding command {} ({}) was not rejected: status={} violations={:?}",
            stale_binding.command_id,
            stale_binding.command,
            stale_binding.status.as_str(),
            stale_binding.violations
        )
        .into());
    }

    let feature_mismatch = semantic.apply_envelope(CommandEnvelope::new(
        233,
        "target-executor-b6",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 20_038,
            name: "virtio-blk0-backend-feature-mismatch".to_owned(),
            block_device: 20_031,
            block_device_generation: 1,
            driver_binding: 20_033,
            driver_binding_generation: 1,
            provider: VIRTIO_BLK_BACKEND_PROVIDER.to_owned(),
            profile: VIRTIO_BLK_BACKEND_PROFILE.to_owned(),
            model: VIRTIO_BLK_BACKEND_MODEL.to_owned(),
            sector_size: config.sector_size,
            sector_count: config.sector_count,
            read_only: config.read_only,
            max_transfer_sectors: config.max_transfer_sectors,
            device_features: config.device_features,
            driver_features: config.driver_features,
            negotiated_features: config.device_features | (1 << 63),
            request_queue_index: config.request_queue_index,
            queue_size: config.queue_size,
            irq_vector: config.irq_vector,
            note: "b6-reject-feature-negotiation-mismatch".to_owned(),
        },
    ));
    if feature_mismatch.status != CommandStatus::Rejected
        || !feature_mismatch
            .violations
            .iter()
            .any(|violation| violation.contains("negotiated features"))
    {
        return Err(format!(
            "block runtime b6 feature mismatch command {} ({}) was not rejected: status={} violations={:?}",
            feature_mismatch.command_id,
            feature_mismatch.command,
            feature_mismatch.status.as_str(),
            feature_mismatch.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b7_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let data_digest = SemanticGraph::expected_block_read_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        64,
        8,
        1,
        4096,
    );
    let read_path = semantic.apply_envelope(CommandEnvelope::new(
        234,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_039,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-record-block-read-path-through-fake-backend".to_owned(),
        },
    ));
    if read_path.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 read path command {} ({}) failed: status={} violations={:?}",
            read_path.command_id,
            read_path.command,
            read_path.status.as_str(),
            read_path.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        235,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_040,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-duplicate-read-path".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already exists for request generation"))
    {
        return Err(format!(
            "block runtime b7 duplicate read path command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        236,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_041,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b7 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let write_request = semantic.apply_envelope(CommandEnvelope::new(
        237,
        "target-executor-b7",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_042,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 4,
            note: "b7-record-write-request-for-read-path-negative".to_owned(),
        },
    ));
    if write_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 write request command {} ({}) failed: status={} violations={:?}",
            write_request.command_id,
            write_request.command,
            write_request.status.as_str(),
            write_request.violations
        )
        .into());
    }
    let write_completion = semantic.apply_envelope(CommandEnvelope::new(
        238,
        "target-executor-b7",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_043,
            block_request: 20_042,
            block_request_generation: 1,
            sequence: 4,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b7-record-write-completion-for-read-path-negative".to_owned(),
        },
    ));
    if write_completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b7 write completion command {} ({}) failed: status={} violations={:?}",
            write_completion.command_id,
            write_completion.command,
            write_completion.status.as_str(),
            write_completion.violations
        )
        .into());
    }
    let write_not_read = semantic.apply_envelope(CommandEnvelope::new(
        239,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_044,
            backend,
            block_request: 20_042,
            block_request_generation: 1,
            block_completion: 20_043,
            block_completion_generation: 1,
            data_digest,
            note: "b7-reject-write-request-as-read-path".to_owned(),
        },
    ));
    if write_not_read.status != CommandStatus::Rejected
        || !write_not_read
            .violations
            .iter()
            .any(|violation| violation.contains("operation is not read"))
    {
        return Err(format!(
            "block runtime b7 write-as-read command {} ({}) was not rejected: status={} violations={:?}",
            write_not_read.command_id,
            write_not_read.command,
            write_not_read.status.as_str(),
            write_not_read.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        240,
        "target-executor-b7",
        SemanticCommand::RecordBlockReadPath {
            read_path: 20_045,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            data_digest: data_digest.wrapping_add(1),
            note: "b7-reject-data-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest.violations.iter().any(|violation| violation.contains("data digest mismatch"))
    {
        return Err(format!(
            "block runtime b7 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b8_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let config = FakeBlockBackendConfig::blk0();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 1);
    let write_request = semantic.apply_envelope(CommandEnvelope::new(
        241,
        "target-executor-b8",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_046,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 5,
            note: "b8-record-write-request".to_owned(),
        },
    ));
    if write_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write request command {} ({}) failed: status={} violations={:?}",
            write_request.command_id,
            write_request.command,
            write_request.status.as_str(),
            write_request.violations
        )
        .into());
    }
    let write_completion = semantic.apply_envelope(CommandEnvelope::new(
        242,
        "target-executor-b8",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_047,
            block_request: 20_046,
            block_request_generation: 1,
            sequence: 5,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b8-record-write-completion".to_owned(),
        },
    ));
    if write_completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write completion command {} ({}) failed: status={} violations={:?}",
            write_completion.command_id,
            write_completion.command,
            write_completion.status.as_str(),
            write_completion.violations
        )
        .into());
    }
    let payload_digest = SemanticGraph::expected_block_write_payload_digest_v1(
        config.deterministic_seed,
        20_002,
        1,
        20_005,
        1,
        64,
        8,
        5,
        4096,
    );
    let write_path = semantic.apply_envelope(CommandEnvelope::new(
        243,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_048,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-record-block-write-path-through-fake-backend".to_owned(),
        },
    ));
    if write_path.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b8 write path command {} ({}) failed: status={} violations={:?}",
            write_path.command_id,
            write_path.command,
            write_path.status.as_str(),
            write_path.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        244,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_049,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-duplicate-write-path".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("already exists for request generation"))
    {
        return Err(format!(
            "block runtime b8 duplicate write path command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    let stale_backend = semantic.apply_envelope(CommandEnvelope::new(
        245,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_050,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 20_026, 2),
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-stale-backend-generation".to_owned(),
        },
    ));
    if stale_backend.status != CommandStatus::Rejected
        || !stale_backend
            .violations
            .iter()
            .any(|violation| violation.contains("backend generation"))
    {
        return Err(format!(
            "block runtime b8 stale backend command {} ({}) was not rejected: status={} violations={:?}",
            stale_backend.command_id,
            stale_backend.command,
            stale_backend.status.as_str(),
            stale_backend.violations
        )
        .into());
    }

    let read_not_write = semantic.apply_envelope(CommandEnvelope::new(
        246,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_051,
            backend,
            block_request: 20_009,
            block_request_generation: 1,
            block_completion: 20_013,
            block_completion_generation: 1,
            payload_digest,
            note: "b8-reject-read-request-as-write-path".to_owned(),
        },
    ));
    if read_not_write.status != CommandStatus::Rejected
        || !read_not_write
            .violations
            .iter()
            .any(|violation| violation.contains("operation is not write"))
    {
        return Err(format!(
            "block runtime b8 read-as-write command {} ({}) was not rejected: status={} violations={:?}",
            read_not_write.command_id,
            read_not_write.command,
            read_not_write.status.as_str(),
            read_not_write.violations
        )
        .into());
    }

    let bad_digest = semantic.apply_envelope(CommandEnvelope::new(
        247,
        "target-executor-b8",
        SemanticCommand::RecordBlockWritePath {
            write_path: 20_052,
            backend,
            block_request: 20_046,
            block_request_generation: 1,
            block_completion: 20_047,
            block_completion_generation: 1,
            payload_digest: payload_digest.wrapping_add(1),
            note: "b8-reject-payload-digest-mismatch".to_owned(),
        },
    ));
    if bad_digest.status != CommandStatus::Rejected
        || !bad_digest
            .violations
            .iter()
            .any(|violation| violation.contains("payload digest mismatch"))
    {
        return Err(format!(
            "block runtime b8 bad digest command {} ({}) was not rejected: status={} violations={:?}",
            bad_digest.command_id,
            bad_digest.command,
            bad_digest.status.as_str(),
            bad_digest.violations
        )
        .into());
    }

    Ok(())
}
