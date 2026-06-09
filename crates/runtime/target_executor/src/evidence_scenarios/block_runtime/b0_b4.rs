use super::*;

pub(crate) fn record_block_runtime_b0_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let block_resource =
        semantic.register_resource(ResourceKind::BlockDevice, None, "block-device:fake-block0");
    let block_resource_generation = semantic
        .resource_handle(block_resource)
        .map(|handle| handle.generation)
        .ok_or("b0 block device resource handle is missing")?;
    if !semantic.record_device_object_with_id(
        20_001,
        "fake-block0",
        "block-device",
        block_resource,
        block_resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "visa",
        "fake-block-v1",
        "b0-record-block-backing-device",
    ) {
        return Err("b0 block backing device could not be recorded".into());
    }

    let block_device = semantic.apply_envelope(CommandEnvelope::new(
        196,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_002,
            name: "blk0".to_owned(),
            device: 20_001,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-record-block-device-object-harness".to_owned(),
        },
    ));
    if block_device.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b0 block device command {} ({}) failed: status={} violations={:?}",
            block_device.command_id,
            block_device.command,
            block_device.status.as_str(),
            block_device.violations
        )
        .into());
    }

    let stale_device = semantic.apply_envelope(CommandEnvelope::new(
        197,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_003,
            name: "blk0-stale".to_owned(),
            device: 20_001,
            device_generation: 2,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-reject-stale-device-generation".to_owned(),
        },
    ));
    if stale_device.status != CommandStatus::Rejected
        || !stale_device.violations.iter().any(|violation| violation.contains("device generation"))
    {
        return Err(format!(
            "block runtime b0 stale device command {} ({}) was not rejected: status={} violations={:?}",
            stale_device.command_id,
            stale_device.command,
            stale_device.status.as_str(),
            stale_device.violations
        )
        .into());
    }

    let bad_contract = semantic.apply_envelope(CommandEnvelope::new(
        198,
        "target-executor-b0",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 20_004,
            name: "blk0-bad-sector".to_owned(),
            device: 20_001,
            device_generation: 1,
            sector_size: 0,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0-reject-zero-sector-size".to_owned(),
        },
    ));
    if bad_contract.status != CommandStatus::Rejected
        || !bad_contract.violations.iter().any(|violation| violation.contains("contract values"))
    {
        return Err(format!(
            "block runtime b0 bad contract command {} ({}) was not rejected: status={} violations={:?}",
            bad_contract.command_id,
            bad_contract.command,
            bad_contract.status.as_str(),
            bad_contract.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b1_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let block_range = semantic.apply_envelope(CommandEnvelope::new(
        199,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_005,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 64,
            sector_count: 8,
            note: "b1-record-sector-range-with-derived-byte-bounds".to_owned(),
        },
    ));
    if block_range.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b1 block range command {} ({}) failed: status={} violations={:?}",
            block_range.command_id,
            block_range.command,
            block_range.status.as_str(),
            block_range.violations
        )
        .into());
    }

    let stale_device = semantic.apply_envelope(CommandEnvelope::new(
        200,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_006,
            block_device: 20_002,
            block_device_generation: 2,
            start_sector: 64,
            sector_count: 8,
            note: "b1-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_device.status != CommandStatus::Rejected
        || !stale_device
            .violations
            .iter()
            .any(|violation| violation.contains("block device generation"))
    {
        return Err(format!(
            "block runtime b1 stale device command {} ({}) was not rejected: status={} violations={:?}",
            stale_device.command_id,
            stale_device.command,
            stale_device.status.as_str(),
            stale_device.violations
        )
        .into());
    }

    let out_of_bounds = semantic.apply_envelope(CommandEnvelope::new(
        201,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_007,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 4090,
            sector_count: 16,
            note: "b1-reject-sector-range-beyond-device".to_owned(),
        },
    ));
    if out_of_bounds.status != CommandStatus::Rejected
        || !out_of_bounds
            .violations
            .iter()
            .any(|violation| violation.contains("beyond block device"))
    {
        return Err(format!(
            "block runtime b1 out-of-bounds command {} ({}) was not rejected: status={} violations={:?}",
            out_of_bounds.command_id,
            out_of_bounds.command,
            out_of_bounds.status.as_str(),
            out_of_bounds.violations
        )
        .into());
    }

    let over_transfer = semantic.apply_envelope(CommandEnvelope::new(
        202,
        "target-executor-b1",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_008,
            block_device: 20_002,
            block_device_generation: 1,
            start_sector: 128,
            sector_count: 129,
            note: "b1-reject-range-over-max-transfer".to_owned(),
        },
    ));
    if over_transfer.status != CommandStatus::Rejected
        || !over_transfer.violations.iter().any(|violation| violation.contains("max transfer"))
    {
        return Err(format!(
            "block runtime b1 over-transfer command {} ({}) was not rejected: status={} violations={:?}",
            over_transfer.command_id,
            over_transfer.command,
            over_transfer.status.as_str(),
            over_transfer.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b2_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let request = semantic.apply_envelope(CommandEnvelope::new(
        203,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_009,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2-record-read-request-over-sector-range".to_owned(),
        },
    ));
    if request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b2 request command {} ({}) failed: status={} violations={:?}",
            request.command_id,
            request.command,
            request.status.as_str(),
            request.violations
        )
        .into());
    }

    let stale_range = semantic.apply_envelope(CommandEnvelope::new(
        204,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_010,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 2,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b2-reject-stale-range-generation".to_owned(),
        },
    ));
    if stale_range.status != CommandStatus::Rejected
        || !stale_range
            .violations
            .iter()
            .any(|violation| violation.contains("block range generation"))
    {
        return Err(format!(
            "block runtime b2 stale range command {} ({}) was not rejected: status={} violations={:?}",
            stale_range.command_id,
            stale_range.command,
            stale_range.status.as_str(),
            stale_range.violations
        )
        .into());
    }

    let mismatched_device = semantic.apply_envelope(CommandEnvelope::new(
        205,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_011,
            block_device: 20_003,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 3,
            note: "b2-reject-request-device-mismatch".to_owned(),
        },
    ));
    if mismatched_device.status != CommandStatus::Rejected
        || !mismatched_device
            .violations
            .iter()
            .any(|violation| violation.contains("block device generation"))
    {
        return Err(format!(
            "block runtime b2 mismatched device command {} ({}) was not rejected: status={} violations={:?}",
            mismatched_device.command_id,
            mismatched_device.command,
            mismatched_device.status.as_str(),
            mismatched_device.violations
        )
        .into());
    }

    let duplicate_sequence = semantic.apply_envelope(CommandEnvelope::new(
        206,
        "target-executor-b2",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_012,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2-reject-duplicate-request-sequence".to_owned(),
        },
    ));
    if duplicate_sequence.status != CommandStatus::Rejected
        || !duplicate_sequence
            .violations
            .iter()
            .any(|violation| violation.contains("sequence already exists"))
    {
        return Err(format!(
            "block runtime b2 duplicate sequence command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_sequence.command_id,
            duplicate_sequence.command,
            duplicate_sequence.status.as_str(),
            duplicate_sequence.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b3_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let completion = semantic.apply_envelope(CommandEnvelope::new(
        207,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_013,
            block_request: 20_009,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-record-completion-for-read-request".to_owned(),
        },
    ));
    if completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b3 completion command {} ({}) failed: status={} violations={:?}",
            completion.command_id,
            completion.command,
            completion.status.as_str(),
            completion.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        208,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_014,
            block_request: 20_009,
            block_request_generation: 2,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-stale-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request
            .violations
            .iter()
            .any(|violation| violation.contains("block request generation"))
    {
        return Err(format!(
            "block runtime b3 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    let duplicate_completion = semantic.apply_envelope(CommandEnvelope::new(
        209,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_015,
            block_request: 20_009,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-duplicate-completion".to_owned(),
        },
    ));
    if duplicate_completion.status != CommandStatus::Rejected
        || !duplicate_completion.violations.iter().any(|violation| {
            violation.contains("not submitted") || violation.contains("already exists")
        })
    {
        return Err(format!(
            "block runtime b3 duplicate completion command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_completion.command_id,
            duplicate_completion.command,
            duplicate_completion.status.as_str(),
            duplicate_completion.violations
        )
        .into());
    }

    let second_request = semantic.apply_envelope(CommandEnvelope::new(
        210,
        "target-executor-b3",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_017,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b3-record-second-request-for-byte-count-negative".to_owned(),
        },
    ));
    if second_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b3 second request command {} ({}) failed: status={} violations={:?}",
            second_request.command_id,
            second_request.command,
            second_request.status.as_str(),
            second_request.violations
        )
        .into());
    }

    let bad_byte_count = semantic.apply_envelope(CommandEnvelope::new(
        211,
        "target-executor-b3",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_016,
            block_request: 20_017,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 2048,
            status: BlockCompletionStatus::Success,
            note: "b3-reject-partial-success".to_owned(),
        },
    ));
    if bad_byte_count.status != CommandStatus::Rejected
        || !bad_byte_count.violations.iter().any(|violation| violation.contains("full byte range"))
    {
        return Err(format!(
            "block runtime b3 bad byte count command {} ({}) was not rejected: status={} violations={:?}",
            bad_byte_count.command_id,
            bad_byte_count.command,
            bad_byte_count.status.as_str(),
            bad_byte_count.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b4_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let block_driver_store = semantic.register_store(
        "b4.block.driver",
        "b4-block-driver.fake-aot",
        "driver",
        "restartable",
    );
    semantic.set_store_state(block_driver_store, StoreState::Running);
    let block_driver_store_generation = semantic
        .store_handle(block_driver_store)
        .map(|handle| handle.generation)
        .ok_or("b4 block driver store handle is missing")?;
    let pending_request_ref =
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 20_017, 1);
    let create_wait = semantic.apply_envelope(CommandEnvelope::new(
        212,
        "target-executor-b4",
        SemanticCommand::CreateWait {
            wait: 20_018,
            owner_task: None,
            owner_store: Some(block_driver_store),
            owner_store_generation: Some(block_driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![pending_request_ref],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-request-pending-completion".to_owned()),
        },
    ));
    if create_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 create wait command {} ({}) failed: status={} violations={:?}",
            create_wait.command_id,
            create_wait.command,
            create_wait.status.as_str(),
            create_wait.violations
        )
        .into());
    }

    let record_wait = semantic.apply_envelope(CommandEnvelope::new(
        213,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_019,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 1,
            note: "b4-record-block-wait-for-request".to_owned(),
        },
    ));
    if record_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 block wait command {} ({}) failed: status={} violations={:?}",
            record_wait.command_id,
            record_wait.command,
            record_wait.status.as_str(),
            record_wait.violations
        )
        .into());
    }

    let duplicate_wait = semantic.apply_envelope(CommandEnvelope::new(
        214,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_020,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 1,
            note: "b4-reject-duplicate-block-wait".to_owned(),
        },
    ));
    if duplicate_wait.status != CommandStatus::Rejected
        || !duplicate_wait
            .violations
            .iter()
            .any(|violation| violation.contains("pending block wait"))
    {
        return Err(format!(
            "block runtime b4 duplicate wait command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_wait.command_id,
            duplicate_wait.command,
            duplicate_wait.status.as_str(),
            duplicate_wait.violations
        )
        .into());
    }

    let stale_request = semantic.apply_envelope(CommandEnvelope::new(
        215,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_021,
            wait: 20_018,
            wait_generation: 1,
            block_request: 20_017,
            block_request_generation: 2,
            note: "b4-reject-stale-block-request-generation".to_owned(),
        },
    ));
    if stale_request.status != CommandStatus::Rejected
        || !stale_request.violations.iter().any(|violation| {
            violation.contains("block request") || violation.contains("block wait token")
        })
    {
        return Err(format!(
            "block runtime b4 stale request command {} ({}) was not rejected: status={} violations={:?}",
            stale_request.command_id,
            stale_request.command,
            stale_request.status.as_str(),
            stale_request.violations
        )
        .into());
    }

    let completion = semantic.apply_envelope(CommandEnvelope::new(
        216,
        "target-executor-b4",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 20_022,
            block_request: 20_017,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b4-record-completion-for-waited-request".to_owned(),
        },
    ));
    if completion.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 completion command {} ({}) failed: status={} violations={:?}",
            completion.command_id,
            completion.command,
            completion.status.as_str(),
            completion.violations
        )
        .into());
    }

    let resolve_wait = semantic.apply_envelope(CommandEnvelope::new(
        217,
        "target-executor-b4",
        SemanticCommand::ResolveBlockWait {
            block_wait: 20_019,
            block_wait_generation: 1,
            block_completion: 20_022,
            block_completion_generation: 1,
            note: "b4-resolve-block-wait-through-completion".to_owned(),
        },
    ));
    if resolve_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 resolve wait command {} ({}) failed: status={} violations={:?}",
            resolve_wait.command_id,
            resolve_wait.command,
            resolve_wait.status.as_str(),
            resolve_wait.violations
        )
        .into());
    }

    let cancel_request = semantic.apply_envelope(CommandEnvelope::new(
        218,
        "target-executor-b4",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_023,
            block_device: 20_002,
            block_device_generation: 1,
            block_range: 20_005,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 3,
            note: "b4-record-cancellable-block-request".to_owned(),
        },
    ));
    if cancel_request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 cancel request command {} ({}) failed: status={} violations={:?}",
            cancel_request.command_id,
            cancel_request.command,
            cancel_request.status.as_str(),
            cancel_request.violations
        )
        .into());
    }
    let cancel_request_ref =
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 20_023, 1);
    let create_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        219,
        "target-executor-b4",
        SemanticCommand::CreateWait {
            wait: 20_024,
            owner_task: None,
            owner_store: Some(block_driver_store),
            owner_store_generation: Some(block_driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![cancel_request_ref],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-request-device-fault".to_owned()),
        },
    ));
    if create_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 create cancel wait command {} ({}) failed: status={} violations={:?}",
            create_cancel_wait.command_id,
            create_cancel_wait.command,
            create_cancel_wait.status.as_str(),
            create_cancel_wait.violations
        )
        .into());
    }
    let record_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        220,
        "target-executor-b4",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_025,
            wait: 20_024,
            wait_generation: 1,
            block_request: 20_023,
            block_request_generation: 1,
            note: "b4-record-cancellable-block-wait".to_owned(),
        },
    ));
    if record_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 record cancel wait command {} ({}) failed: status={} violations={:?}",
            record_cancel_wait.command_id,
            record_cancel_wait.command,
            record_cancel_wait.status.as_str(),
            record_cancel_wait.violations
        )
        .into());
    }
    let cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        221,
        "target-executor-b4",
        SemanticCommand::CancelBlockWait {
            block_wait: 20_025,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4-cancel-block-wait-on-device-fault".to_owned(),
        },
    ));
    if cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b4 cancel wait command {} ({}) failed: status={} violations={:?}",
            cancel_wait.command_id,
            cancel_wait.command,
            cancel_wait.status.as_str(),
            cancel_wait.violations
        )
        .into());
    }

    Ok(())
}
