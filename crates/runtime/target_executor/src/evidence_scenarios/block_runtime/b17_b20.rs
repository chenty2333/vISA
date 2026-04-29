use super::*;

pub(crate) fn record_block_runtime_b17_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let owner_store = semantic_store_id(semantic, "linux_syscall")?;
    let file_ref = ContractObjectRef::new(ContractObjectKind::FileObject, 20_073, 1);
    let capability = semantic.grant_capability_with_authority_ref(
        "linux_syscall",
        "file-handle./demo/file.txt",
        AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_ref),
        &["read", "write"],
        "task",
        "target-executor-b17",
        true,
    );
    let capability_record = semantic
        .capabilities()
        .record(capability)
        .ok_or("block runtime b17 file handle capability record is missing")?;
    let capability_generation = capability_record.generation;
    let owner_store_generation = capability_record
        .owner_store_generation
        .ok_or("block runtime b17 file handle capability owner generation is missing")?;
    let handle = capability_record
        .store_local_handle(vec!["read".to_owned()])
        .ok_or("block runtime b17 file handle capability handle is missing")?;

    let allowed = semantic.apply_envelope(CommandEnvelope::new(
        284,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_089,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-allow-file-handle-read".to_owned(),
        },
    ));
    if allowed.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b17 file handle command {} ({}) failed: status={} violations={:?}",
            allowed.command_id,
            allowed.command,
            allowed.status.as_str(),
            allowed.violations
        )
        .into());
    }

    let stale_file = semantic.apply_envelope(CommandEnvelope::new(
        285,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_090,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 2,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-stale-file-generation".to_owned(),
        },
    ));
    if stale_file.status != CommandStatus::Rejected
        || !stale_file.violations.iter().any(|violation| violation.contains("file generation"))
    {
        return Err(format!(
            "block runtime b17 stale file command {} ({}) was not rejected: status={} violations={:?}",
            stale_file.command_id,
            stale_file.command,
            stale_file.status.as_str(),
            stale_file.violations
        )
        .into());
    }

    let mut forged_handle = handle.clone();
    forged_handle.generation = forged_handle.generation.saturating_add(1);
    let forged = semantic.apply_envelope(CommandEnvelope::new(
        286,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_091,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: forged_handle,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-forged-file-handle-generation".to_owned(),
        },
    ));
    if forged.status != CommandStatus::Rejected
        || !forged.violations.iter().any(|violation| violation.contains("handle is not authorized"))
    {
        return Err(format!(
            "block runtime b17 forged handle command {} ({}) was not rejected: status={} violations={:?}",
            forged.command_id,
            forged.command,
            forged.status.as_str(),
            forged.violations
        )
        .into());
    }

    let oversized = semantic.apply_envelope(CommandEnvelope::new(
        287,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_092,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle: handle.clone(),
            operation: "read".to_owned(),
            file_offset: 4090,
            byte_len: 16,
            content_digest: 0xB13,
            note: "b17-reject-oversized-file-handle-range".to_owned(),
        },
    ));
    if oversized.status != CommandStatus::Rejected
        || !oversized.violations.iter().any(|violation| violation.contains("file binding mismatch"))
    {
        return Err(format!(
            "block runtime b17 oversized file command {} ({}) was not rejected: status={} violations={:?}",
            oversized.command_id,
            oversized.command,
            oversized.status.as_str(),
            oversized.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        288,
        "target-executor-b17",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 20_093,
            owner_store,
            owner_store_generation,
            file_object: 20_073,
            file_object_generation: 1,
            directory_object: 20_077,
            directory_object_generation: 1,
            capability,
            capability_generation,
            handle,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17-reject-duplicate-file-handle-read".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate.violations.iter().any(|violation| violation.contains("already allowed"))
    {
        return Err(format!(
            "block runtime b17 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b18_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let capability = semantic
        .file_handle_capabilities()
        .iter()
        .find(|record| record.id == 20_089 && record.generation == 1)
        .cloned()
        .ok_or("block runtime b18 file handle capability evidence is missing")?;
    let blocker = capability.object_ref();

    let create_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        289,
        "target-executor-b18",
        SemanticCommand::CreateWait {
            wait: 20_094,
            owner_task: None,
            owner_store: Some(capability.owner_store),
            owner_store_generation: Some(capability.owner_store_generation),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18-fs-read-wait-pending".to_owned()),
        },
    ));
    if create_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 create read wait command {} ({}) failed: status={} violations={:?}",
            create_read_wait.command_id,
            create_read_wait.command,
            create_read_wait.status.as_str(),
            create_read_wait.violations
        )
        .into());
    }

    let record_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        290,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_095,
            wait: 20_094,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 1,
            note: "b18-record-fs-read-wait".to_owned(),
        },
    ));
    if record_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 record read wait command {} ({}) failed: status={} violations={:?}",
            record_read_wait.command_id,
            record_read_wait.command,
            record_read_wait.status.as_str(),
            record_read_wait.violations
        )
        .into());
    }

    let resolve_read_wait = semantic.apply_envelope(CommandEnvelope::new(
        291,
        "target-executor-b18",
        SemanticCommand::ResolveFsWait {
            fs_wait: 20_095,
            fs_wait_generation: 1,
            note: "b18-resolve-fs-read-wait".to_owned(),
        },
    ));
    if resolve_read_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 resolve read wait command {} ({}) failed: status={} violations={:?}",
            resolve_read_wait.command_id,
            resolve_read_wait.command,
            resolve_read_wait.status.as_str(),
            resolve_read_wait.violations
        )
        .into());
    }

    let create_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        292,
        "target-executor-b18",
        SemanticCommand::CreateWait {
            wait: 20_096,
            owner_task: None,
            owner_store: Some(capability.owner_store),
            owner_store_generation: Some(capability.owner_store_generation),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18-fs-read-wait-close-fd".to_owned()),
        },
    ));
    if create_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 create cancel wait command {} ({}) failed: status={} violations={:?}",
            create_cancel_wait.command_id,
            create_cancel_wait.command,
            create_cancel_wait.status.as_str(),
            create_cancel_wait.violations
        )
        .into());
    }

    let record_cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        293,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_097,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 2,
            note: "b18-record-cancellable-fs-wait".to_owned(),
        },
    ));
    if record_cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 record cancel wait command {} ({}) failed: status={} violations={:?}",
            record_cancel_wait.command_id,
            record_cancel_wait.command,
            record_cancel_wait.status.as_str(),
            record_cancel_wait.violations
        )
        .into());
    }

    let duplicate_pending = semantic.apply_envelope(CommandEnvelope::new(
        294,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_098,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation,
            operation: "read".to_owned(),
            sequence: 2,
            note: "b18-reject-duplicate-pending-fs-wait".to_owned(),
        },
    ));
    if duplicate_pending.status != CommandStatus::Rejected
        || !duplicate_pending
            .violations
            .iter()
            .any(|violation| violation.contains("pending fs wait"))
    {
        return Err(format!(
            "block runtime b18 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate_pending.command_id,
            duplicate_pending.command,
            duplicate_pending.status.as_str(),
            duplicate_pending.violations
        )
        .into());
    }

    let stale_handle = semantic.apply_envelope(CommandEnvelope::new(
        295,
        "target-executor-b18",
        SemanticCommand::RecordFsWait {
            fs_wait: 20_099,
            wait: 20_096,
            wait_generation: 1,
            file_handle_capability: capability.id,
            file_handle_capability_generation: capability.generation.saturating_add(1),
            operation: "read".to_owned(),
            sequence: 3,
            note: "b18-reject-stale-file-handle-capability-generation".to_owned(),
        },
    ));
    if stale_handle.status != CommandStatus::Rejected
        || !stale_handle
            .violations
            .iter()
            .any(|violation| violation.contains("file handle capability generation"))
    {
        return Err(format!(
            "block runtime b18 stale handle command {} ({}) was not rejected: status={} violations={:?}",
            stale_handle.command_id,
            stale_handle.command,
            stale_handle.status.as_str(),
            stale_handle.violations
        )
        .into());
    }

    let cancel_wait = semantic.apply_envelope(CommandEnvelope::new(
        296,
        "target-executor-b18",
        SemanticCommand::CancelFsWait {
            fs_wait: 20_097,
            fs_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "b18-cancel-fs-wait-on-close-fd".to_owned(),
        },
    ));
    if cancel_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b18 cancel wait command {} ({}) failed: status={} violations={:?}",
            cancel_wait.command_id,
            cancel_wait.command,
            cancel_wait.status.as_str(),
            cancel_wait.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b19_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("block runtime b19 driver store is missing")?;
    let driver_store_generation = semantic
        .store_handle(driver_store)
        .map(|handle| handle.generation)
        .ok_or("block runtime b19 driver store generation is missing")?;

    let range = semantic.apply_envelope(CommandEnvelope::new(
        297,
        "target-executor-b19",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 20_100,
            block_device: 20_031,
            block_device_generation: 1,
            start_sector: 8,
            sector_count: 8,
            note: "b19-record-cleanup-target-range".to_owned(),
        },
    ));
    if range.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b19 range command {} ({}) failed: status={} violations={:?}",
            range.command_id,
            range.command,
            range.status.as_str(),
            range.violations
        )
        .into());
    }

    let request = semantic.apply_envelope(CommandEnvelope::new(
        298,
        "target-executor-b19",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 20_101,
            block_device: 20_031,
            block_device_generation: 1,
            block_range: 20_100,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b19-record-pending-cleanup-request".to_owned(),
        },
    ));
    if request.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b19 request command {} ({}) failed: status={} violations={:?}",
            request.command_id,
            request.command,
            request.status.as_str(),
            request.violations
        )
        .into());
    }

    let request_ref = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 20_101, 1);
    let create_wait = semantic.apply_envelope(CommandEnvelope::new(
        299,
        "target-executor-b19",
        SemanticCommand::CreateWait {
            wait: 20_102,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![request_ref],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b19-block-driver-cleanup-pending-request".to_owned()),
        },
    ));
    if create_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b19 create wait command {} ({}) failed: status={} violations={:?}",
            create_wait.command_id,
            create_wait.command,
            create_wait.status.as_str(),
            create_wait.violations
        )
        .into());
    }

    let block_wait = semantic.apply_envelope(CommandEnvelope::new(
        300,
        "target-executor-b19",
        SemanticCommand::RecordBlockWait {
            block_wait: 20_103,
            wait: 20_102,
            wait_generation: 1,
            block_request: 20_101,
            block_request_generation: 1,
            note: "b19-record-cleanup-cancellable-block-wait".to_owned(),
        },
    ));
    if block_wait.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b19 block wait command {} ({}) failed: status={} violations={:?}",
            block_wait.command_id,
            block_wait.command,
            block_wait.status.as_str(),
            block_wait.violations
        )
        .into());
    }

    let dma_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:virtio-blk0-b19");
    let dma_resource_generation = semantic
        .resource_handle(dma_resource)
        .map(|handle| handle.generation)
        .ok_or("b19 dma resource handle is missing")?;

    let commands = [
        CommandEnvelope::new(
            301,
            "target-executor-b19",
            SemanticCommand::RecordQueueObject {
                queue: 20_104,
                name: "virtio-blk0-b19-submit".to_owned(),
                role: QueueObjectRole::Submission,
                queue_index: 2,
                depth: 16,
                device: 20_030,
                device_generation: 1,
                note: "b19-record-cleanup-dma-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            302,
            "target-executor-b19",
            SemanticCommand::RecordDescriptorObject {
                descriptor: 20_105,
                queue: 20_104,
                queue_generation: 1,
                slot: 0,
                access: DescriptorObjectAccess::ReadWrite,
                length: 4096,
                note: "b19-record-cleanup-dma-descriptor".to_owned(),
            },
        ),
        CommandEnvelope::new(
            303,
            "target-executor-b19",
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer: 20_106,
                descriptor: 20_105,
                descriptor_generation: 1,
                resource: dma_resource,
                resource_generation: dma_resource_generation,
                access: DmaBufferObjectAccess::ReadWrite,
                length: 4096,
                note: "b19-record-cleanup-owned-dma-buffer".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b19 setup command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        304,
        "target-executor-b19",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 20_109,
            io_cleanup: 20_110,
            block_device: 20_031,
            block_device_generation: 2,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 20_034, 1),
            reason: "virtio-blk-device-fault".to_owned(),
            note: "b19-reject-stale-block-device-generation".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("block device generation"))
    {
        return Err(format!(
            "block runtime b19 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    let cleanup = semantic.apply_envelope(CommandEnvelope::new(
        305,
        "target-executor-b19",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 20_107,
            io_cleanup: 20_108,
            block_device: 20_031,
            block_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 20_034, 1),
            reason: "virtio-blk-device-fault".to_owned(),
            note: "b19-cleanup-disk-driver-fault".to_owned(),
        },
    ));
    if cleanup.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b19 cleanup command {} ({}) failed: status={} violations={:?}",
            cleanup.command_id,
            cleanup.command,
            cleanup.status.as_str(),
            cleanup.violations
        )
        .into());
    }

    let record = semantic
        .block_driver_cleanups()
        .iter()
        .find(|record| record.id == 20_107 && record.generation == 1)
        .ok_or("block runtime b19 cleanup record is missing")?;
    if record.cancelled_block_waits.len() != 1
        || record.cancelled_wait_tokens.len() != 1
        || record.released_dma_buffers.len() != 1
        || record.revoked_device_capabilities.is_empty()
    {
        return Err(format!(
            "block runtime b19 cleanup effects are incomplete: block_waits={} wait_tokens={} dma_buffers={} device_caps={}",
            record.cancelled_block_waits.len(),
            record.cancelled_wait_tokens.len(),
            record.released_dma_buffers.len(),
            record.revoked_device_capabilities.len()
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b20_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let driver_store =
        semantic.store_id("b4.block.driver").ok_or("block runtime b20 driver store is missing")?;
    let driver_store_generation = semantic
        .store_handle(driver_store)
        .map(|handle| handle.generation)
        .ok_or("block runtime b20 driver store generation is missing")?;

    let commands = [
        CommandEnvelope::new(
            306,
            "target-executor-b20",
            SemanticCommand::RecordBlockRequestObject {
                block_request: 20_111,
                block_device: 20_002,
                block_device_generation: 1,
                block_range: 20_005,
                block_range_generation: 1,
                operation: BlockRequestOperation::Read,
                sequence: 1000,
                note: "b20-record-retry-original-request".to_owned(),
            },
        ),
        CommandEnvelope::new(
            307,
            "target-executor-b20",
            SemanticCommand::RecordBlockRequestObject {
                block_request: 20_112,
                block_device: 20_002,
                block_device_generation: 1,
                block_range: 20_005,
                block_range_generation: 1,
                operation: BlockRequestOperation::Read,
                sequence: 1001,
                note: "b20-record-retry-reissued-request".to_owned(),
            },
        ),
        CommandEnvelope::new(
            308,
            "target-executor-b20",
            SemanticCommand::RecordBlockRequestObject {
                block_request: 20_116,
                block_device: 20_002,
                block_device_generation: 1,
                block_range: 20_005,
                block_range_generation: 1,
                operation: BlockRequestOperation::Read,
                sequence: 1002,
                note: "b20-record-eio-request".to_owned(),
            },
        ),
        CommandEnvelope::new(
            309,
            "target-executor-b20",
            SemanticCommand::RecordBlockRequestObject {
                block_request: 20_119,
                block_device: 20_002,
                block_device_generation: 1,
                block_range: 20_005,
                block_range_generation: 1,
                operation: BlockRequestOperation::Read,
                sequence: 1003,
                note: "b20-record-cancel-request".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b20 request command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    for (command_id, wait, request, saved_context) in [
        (310, 20_113, 20_111, "b20-pending-io-retry-original-request"),
        (311, 20_117, 20_116, "b20-pending-io-eio-request"),
        (312, 20_120, 20_119, "b20-pending-io-cancel-request"),
    ] {
        let result = semantic.apply_envelope(CommandEnvelope::new(
            command_id,
            "target-executor-b20",
            SemanticCommand::CreateWait {
                wait,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DriverCompletion,
                generation: 1,
                blockers: vec![ContractObjectRef::new(
                    ContractObjectKind::BlockRequestObject,
                    request,
                    1,
                )],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some(saved_context.to_owned()),
            },
        ));
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b20 create wait command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    for (command_id, block_wait, wait, request, note) in [
        (313, 20_114, 20_113, 20_111, "b20-record-retry-block-wait"),
        (314, 20_118, 20_117, 20_116, "b20-record-eio-block-wait"),
        (315, 20_121, 20_120, 20_119, "b20-record-cancel-block-wait"),
    ] {
        let result = semantic.apply_envelope(CommandEnvelope::new(
            command_id,
            "target-executor-b20",
            SemanticCommand::RecordBlockWait {
                block_wait,
                wait,
                wait_generation: 1,
                block_request: request,
                block_request_generation: 1,
                note: note.to_owned(),
            },
        ));
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b20 block wait command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_retry = semantic.apply_envelope(CommandEnvelope::new(
        316,
        "target-executor-b20",
        SemanticCommand::ApplyBlockPendingIoPolicy {
            policy: 20_122,
            block_wait: 20_114,
            block_wait_generation: 1,
            action: BlockPendingIoAction::Retry,
            retry_request: Some(20_112),
            retry_request_generation: Some(2),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            note: "b20-reject-stale-retry-request-generation".to_owned(),
        },
    ));
    if stale_retry.status != CommandStatus::Rejected
        || !stale_retry
            .violations
            .iter()
            .any(|violation| violation.contains("retry request generation"))
    {
        return Err(format!(
            "block runtime b20 stale retry command {} ({}) was not rejected: status={} violations={:?}",
            stale_retry.command_id,
            stale_retry.command,
            stale_retry.status.as_str(),
            stale_retry.violations
        )
        .into());
    }

    for command in [
        CommandEnvelope::new(
            317,
            "target-executor-b20",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 20_123,
                block_wait: 20_114,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Retry,
                retry_request: Some(20_112),
                retry_request_generation: Some(1),
                errno: 11,
                retry_attempt: 1,
                max_retries: 2,
                note: "b20-retry-pending-block-io".to_owned(),
            },
        ),
        CommandEnvelope::new(
            318,
            "target-executor-b20",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 20_124,
                block_wait: 20_118,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Eio,
                retry_request: None,
                retry_request_generation: None,
                errno: 5,
                retry_attempt: 0,
                max_retries: 0,
                note: "b20-return-eio-for-pending-block-io".to_owned(),
            },
        ),
        CommandEnvelope::new(
            319,
            "target-executor-b20",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 20_125,
                block_wait: 20_121,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Cancel,
                retry_request: None,
                retry_request_generation: None,
                errno: 125,
                retry_attempt: 0,
                max_retries: 0,
                note: "b20-cancel-pending-block-io".to_owned(),
            },
        ),
    ] {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "block runtime b20 policy command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    if semantic.block_pending_io_policy_count() != 3 {
        return Err(format!(
            "block runtime b20 expected 3 policy records, got {}",
            semantic.block_pending_io_policy_count()
        )
        .into());
    }
    if !semantic.block_pending_io_policies().iter().any(|policy| {
        policy.id == 20_123
            && policy.action == BlockPendingIoAction::Retry
            && policy.retry_request == Some(20_112)
            && policy.state.as_str() == "retry-scheduled"
    }) {
        return Err("block runtime b20 retry policy evidence is missing".into());
    }

    Ok(())
}
