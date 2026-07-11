use super::*;

pub(super) fn setup_b17_file_handle_capability_graph()
-> (SemanticGraph, CapabilityHandle, CapabilityId) {
    let mut graph = setup_b16_ext4_adapter_graph();
    graph.register_store("linux_syscall", "linux_syscall.wasm", "personality", "kill-on-trap");
    let file_ref = ContractObjectRef::new(ContractObjectKind::FileObject, 1845, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "linux_syscall",
        "file-handle./demo/file.txt",
        AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_ref),
        &["read", "write"],
        "task",
        "b17-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["read".to_string()]))
        .unwrap();
    (graph, handle, cap)
}

#[test]
pub(super) fn block_runtime_b17_file_handle_capability_gates_file_object() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1865,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17 record file handle read capability".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.file_handle_capability_count(), 1);
    let gate = &graph.file_handle_capabilities()[0];
    assert_eq!(
        gate.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1)
    );
    assert_eq!(gate.owner_store, store);
    assert_eq!(gate.file_object, 1845);
    assert_eq!(gate.directory_object, 1850);
    assert_eq!(gate.capability, cap);
    assert_eq!(gate.capability_generation, cap_generation);
    assert_eq!(gate.handle_slot, handle.slot);
    assert_eq!(gate.handle_generation, handle.generation);
    assert_eq!(gate.handle_tag, handle.tag);
    assert_eq!(gate.operation, "read");
    assert_eq!(gate.byte_len, 512);
    assert_eq!(gate.content_digest, 0xB13);
    assert_eq!(gate.state, FileHandleCapabilityState::Allowed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FileHandleCapabilityRecorded file_handle_capability=1865 owner_store={store}@1 file_object=1845@1 directory_object=1850@1 capability={cap}@{cap_generation} handle_slot={} handle_generation={} handle_tag={} operation=read file_offset=0 byte_len=512 content_digest=2835 state=allowed generation=1",
            handle.slot, handle.generation, handle.tag
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b17_rejects_stale_handle_duplicate_and_oversized_file_gate() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();

    let stale_file = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1866,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 2,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "stale file generation".to_string(),
        },
    ));
    assert_eq!(stale_file.status, CommandStatus::Rejected);
    assert_eq!(
        stale_file.violations,
        vec!["file handle capability file generation is missing".to_string()]
    );

    let mut forged_handle = handle.clone();
    forged_handle.generation = forged_handle.generation.saturating_add(1);
    let bad_handle = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1867,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: forged_handle,
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "forged handle generation".to_string(),
        },
    ));
    assert_eq!(bad_handle.status, CommandStatus::Rejected);
    assert_eq!(
        bad_handle.violations,
        vec!["file handle capability handle is not authorized".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1868,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 4090,
            byte_len: 16,
            content_digest: 0xB13,
            note: "oversized file range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["file handle capability file binding mismatch".to_string()]
    );

    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle.clone(),
        "read",
        0,
        512,
        0xB13,
        "existing file handle capability",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1869,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle,
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "duplicate file handle capability".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["file handle capability already allowed for file operation".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b17_invariants_reject_file_handle_generation_leak() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();
    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle,
        "read",
        0,
        512,
        0xB13,
        "b17 invariant file handle capability",
    ));
    graph.corrupt_file_handle_capability_generation_for_test(1865, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FileHandleCapabilityMissingFileObject {
            file_handle_capability: 1865,
            file_object: 1845,
        })
    );
}

pub(super) fn setup_b18_fs_wait_graph() -> SemanticGraph {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();
    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle,
        "read",
        0,
        512,
        0xB13,
        "b18 file handle capability",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b18_fs_wait_resolves_through_wait_token() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    let create = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b18-test",
        SemanticCommand::CreateWait {
            wait: 1870,
            owner_task: None,
            owner_store: Some(store),
            owner_store_generation: Some(1),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18 fs read wait".to_string()),
        },
    ));
    assert_eq!(create.status, CommandStatus::Applied);

    let record = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1871,
            wait: 1870,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 1,
            operation: "read".to_string(),
            sequence: 1,
            note: "record fs wait".to_string(),
        },
    ));
    assert_eq!(record.status, CommandStatus::Applied);
    assert_eq!(graph.fs_wait_count(), 1);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Pending);
    assert_eq!(
        graph.fs_waits()[0].object_ref(),
        ContractObjectRef::new(ContractObjectKind::FsWait, 1871, 1)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FsWaitCreated fs_wait=1871 wait=1870@1 owner_store={store}@1 file_object=1845@1 directory_object=1850@1 file_handle_capability=1865@1 operation=read blocker=file-handle-capability:1865@1 sequence=1 byte_len=512 generation=1"
        )
    );

    let resolve = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b18-test",
        SemanticCommand::ResolveFsWait {
            fs_wait: 1871,
            fs_wait_generation: 1,
            note: "resolve fs wait".to_string(),
        },
    ));
    assert_eq!(resolve.status, CommandStatus::Applied);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Resolved);
    assert_eq!(graph.wait_index().by_store.iter().filter(|(_, _, wait)| *wait == 1870).count(), 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FsWaitResolved fs_wait=1871 wait=1870@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b18_rejects_stale_or_duplicate_fs_wait_and_cancels_closefd() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                4,
                "b18-test",
                SemanticCommand::CreateWait {
                    wait: 1872,
                    owner_task: None,
                    owner_store: Some(store),
                    owner_store_generation: Some(1),
                    kind: SemanticWaitKind::FdReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("b18 cancellable fs wait".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                5,
                "b18-test",
                SemanticCommand::RecordFsWait {
                    fs_wait: 1873,
                    wait: 1872,
                    wait_generation: 1,
                    file_handle_capability: 1865,
                    file_handle_capability_generation: 1,
                    operation: "read".to_string(),
                    sequence: 2,
                    note: "record cancellable fs wait".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1874,
            wait: 1872,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 1,
            operation: "read".to_string(),
            sequence: 2,
            note: "duplicate pending fs wait".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["fs wait token already has a pending fs wait".to_string()]
    );

    let stale = graph.apply_envelope(CommandEnvelope::new(
        7,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1875,
            wait: 1872,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 2,
            operation: "read".to_string(),
            sequence: 3,
            note: "stale file handle generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["fs wait file handle capability generation is missing or not allowed".to_string()]
    );

    let cancel = graph.apply_envelope(CommandEnvelope::new(
        8,
        "b18-test",
        SemanticCommand::CancelFsWait {
            fs_wait: 1873,
            fs_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "close fd cancels fs wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Cancelled);
    assert_eq!(graph.fs_waits()[0].cancel_reason, Some(WaitCancelReason::CloseFd));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FsWaitCancelled fs_wait=1873 wait=1872@1 reason=close-fd generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b18_invariants_reject_file_handle_generation_leak() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    graph.record_wait_created_with_details(
        1876,
        None,
        Some(store),
        Some(1),
        SemanticWaitKind::FdReadable,
        1,
        vec![blocker],
        None,
        RestartPolicy::RestartIfAllowed,
        Some("b18 invariant fs wait".to_string()),
    );
    assert!(graph.record_fs_wait_with_id(
        1877,
        1876,
        1,
        1865,
        1,
        "read",
        4,
        "b18 invariant fs wait",
    ));
    graph.corrupt_fs_wait_file_handle_generation_for_test(1877, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FsWaitMissingFileHandleCapability {
            fs_wait: 1877,
            file_handle_capability: 1865,
        })
    );
}

pub(super) fn setup_b19_block_driver_cleanup_graph() -> SemanticGraph {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "b19-setup",
                SemanticCommand::RecordVirtioBlkBackendObject {
                    virtio_blk_backend: 1880,
                    name: "virtio-blk0-cleanup-backend".to_string(),
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
                    note: "b19 cleanup backend".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_block_range_object_with_id(1881, 1791, 1, 8, 8, "b19 cleanup range",));
    assert!(graph.record_block_request_object_with_id(
        1882,
        1791,
        1,
        1881,
        1,
        BlockRequestOperation::Read,
        1,
        "b19 pending request",
    ));
    let store = graph.store_id("driver.virtio-blk0").unwrap();
    let store_generation = graph.store_handle(store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1882, 1);
    graph.record_wait_created_with_details(
        1883,
        None,
        Some(store),
        Some(store_generation),
        SemanticWaitKind::DriverCompletion,
        1,
        vec![blocker],
        None,
        RestartPolicy::InternalOnly,
        Some("b19 pending block wait".to_string()),
    );
    assert_eq!(graph.check_invariants(), Ok(()));
    assert!(graph.record_block_wait_with_id(1884, 1883, 1, 1882, 1, "b19 pending block wait",));
    assert!(graph.record_queue_object_with_id(
        1885,
        "virtio-blk0-cleanup-submit",
        QueueObjectRole::Submission,
        1,
        8,
        1790,
        1,
        "b19 cleanup queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1886,
        1885,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b19 cleanup descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:b19-cleanup");
    let dma_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1887,
        1886,
        1,
        dma_resource,
        dma_generation,
        DmaBufferObjectAccess::ReadWrite,
        4096,
        "b19 cleanup dma buffer",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b19_disk_driver_fault_cleanup_cancels_wait_and_releases_authority() {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b19-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1888,
            io_cleanup: 1889,
            block_device: 1791,
            block_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b19 cleanup disk driver".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_driver_cleanup_count(), 1);
    let cleanup = &graph.block_driver_cleanups()[0];
    assert_eq!(
        cleanup.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDriverCleanup, 1888, 1)
    );
    assert_eq!(cleanup.state, BlockDriverCleanupState::Completed);
    assert_eq!(cleanup.cancelled_block_waits.len(), 1);
    assert_eq!(cleanup.cancelled_wait_tokens.len(), 1);
    assert_eq!(cleanup.released_dma_buffers.len(), 1);
    assert_eq!(cleanup.revoked_device_capabilities.len(), 1);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Cancelled);
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph.dma_buffer_objects().iter().find(|record| record.id == 1887).unwrap().state,
        DmaBufferObjectState::Released
    );
    assert_eq!(
        graph.driver_store_bindings().iter().find(|record| record.id == 1793).unwrap().state,
        DriverStoreBindingState::Released
    );
    assert_eq!(
        graph.virtio_blk_backends().iter().find(|record| record.id == 1880).unwrap().state,
        VirtioBlkBackendObjectState::Retired
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockDriverCleanupCompleted cleanup=1888 io_cleanup=1889@1 cancelled_block_waits=1 released_dma_buffers=1 revoked_device_capabilities=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b19_rejects_stale_cleanup_and_detects_effect_generation_leak() {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b19-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1890,
            io_cleanup: 1891,
            block_device: 1791,
            block_device_generation: 2,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b19 stale cleanup".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["block driver cleanup block device generation is missing or inactive".to_string()]
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                4,
                "b19-test",
                SemanticCommand::CleanupBlockDriver {
                    cleanup: 1888,
                    io_cleanup: 1889,
                    block_device: 1791,
                    block_device_generation: 1,
                    backend: ContractObjectRef::new(
                        ContractObjectKind::VirtioBlkBackendObject,
                        1880,
                        1,
                    ),
                    reason: "virtio-blk-device-fault".to_string(),
                    note: "b19 cleanup disk driver".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.corrupt_block_driver_cleanup_wait_generation_for_test(1888, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDriverCleanupMissingEffectTarget {
            cleanup: 1888,
            target: ContractObjectRef::new(ContractObjectKind::BlockWait, 1884, 2),
        })
    );
}

pub(super) fn setup_b20_pending_io_policy_graph() -> SemanticGraph {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    assert!(graph.record_block_request_object_with_id(
        1891,
        1791,
        1,
        1881,
        1,
        BlockRequestOperation::Read,
        2,
        "b20 retry request",
    ));
    let store = graph.store_id("driver.virtio-blk0").unwrap();
    let store_generation = graph.store_handle(store).unwrap().generation;
    for (request, wait, block_wait, sequence) in [(1893, 1894, 1895, 3), (1896, 1897, 1898, 4)] {
        assert!(graph.record_block_request_object_with_id(
            request,
            1791,
            1,
            1881,
            1,
            BlockRequestOperation::Read,
            sequence,
            "b20 pending request",
        ));
        graph.record_wait_created_with_details(
            wait,
            None,
            Some(store),
            Some(store_generation),
            SemanticWaitKind::DriverCompletion,
            1,
            vec![ContractObjectRef::new(ContractObjectKind::BlockRequestObject, request, 1)],
            None,
            RestartPolicy::InternalOnly,
            Some("b20 pending block wait".to_string()),
        );
        assert!(graph.record_block_wait_with_id(
            block_wait,
            wait,
            1,
            request,
            1,
            "b20 pending block wait",
        ));
    }
    graph
}

#[test]
pub(super) fn block_runtime_b20_pending_io_policy_records_retry_eio_and_cancel() {
    let mut graph = setup_b20_pending_io_policy_graph();
    for command in [
        CommandEnvelope::new(
            1,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1892,
                block_wait: 1884,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Retry,
                retry_request: Some(1891),
                retry_request_generation: Some(1),
                errno: 11,
                retry_attempt: 1,
                max_retries: 2,
                note: "retry pending block io".to_string(),
            },
        ),
        CommandEnvelope::new(
            2,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1899,
                block_wait: 1895,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Eio,
                retry_request: None,
                retry_request_generation: None,
                errno: 5,
                retry_attempt: 0,
                max_retries: 0,
                note: "return eio".to_string(),
            },
        ),
        CommandEnvelope::new(
            3,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1900,
                block_wait: 1898,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Cancel,
                retry_request: None,
                retry_request_generation: None,
                errno: 125,
                retry_attempt: 0,
                max_retries: 0,
                note: "cancel pending io".to_string(),
            },
        ),
    ] {
        let result = graph.apply_envelope(command);
        assert_eq!(result.status, CommandStatus::Applied);
    }

    assert_eq!(graph.block_pending_io_policy_count(), 3);
    let retry = graph.block_pending_io_policies().iter().find(|record| record.id == 1892).unwrap();
    assert_eq!(retry.action, BlockPendingIoAction::Retry);
    assert_eq!(retry.retry_request, Some(1891));
    assert_eq!(retry.state, BlockPendingIoPolicyState::RetryScheduled);
    assert_eq!(
        graph.block_waits().iter().find(|record| record.id == 1884).unwrap().cancel_reason,
        Some(WaitCancelReason::DeviceFault)
    );
    assert_eq!(
        graph.block_pending_io_policies().iter().find(|record| record.id == 1899).unwrap().state,
        BlockPendingIoPolicyState::EioReturned
    );
    assert_eq!(
        graph.block_waits().iter().find(|record| record.id == 1898).unwrap().cancel_reason,
        Some(WaitCancelReason::ResourceDropped)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockPendingIoPolicyApplied policy=1900 block_wait=1898@1 wait=1897@1 block_request=1896@1 retry_request=none block_device=1791@1 block_range=1881@1 action=cancel errno=125 retry_attempt=0 max_retries=0 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b20_rejects_stale_retry_and_detects_policy_generation_leak() {
    let mut graph = setup_b20_pending_io_policy_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b20-test",
        SemanticCommand::ApplyBlockPendingIoPolicy {
            policy: 1901,
            block_wait: 1884,
            block_wait_generation: 1,
            action: BlockPendingIoAction::Retry,
            retry_request: Some(1891),
            retry_request_generation: Some(2),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            note: "stale retry generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["retry policy retry request generation is missing or not submitted".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                5,
                "b20-test",
                SemanticCommand::ApplyBlockPendingIoPolicy {
                    policy: 1892,
                    block_wait: 1884,
                    block_wait_generation: 1,
                    action: BlockPendingIoAction::Retry,
                    retry_request: Some(1891),
                    retry_request_generation: Some(1),
                    errno: 11,
                    retry_attempt: 1,
                    max_retries: 2,
                    note: "retry pending block io".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.corrupt_block_pending_io_policy_retry_generation_for_test(1892, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockPendingIoPolicyMissingRetryRequest {
            policy: 1892,
            block_request: 1891,
        })
    );
}

#[test]
pub(super) fn block_runtime_b21_records_stale_block_request_generation_audit() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let dma_buffer = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1);

    let stale_completion = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b21-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1840,
            block_request: 1828,
            block_request_generation: 2,
            sequence: 2,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b21 stale completion generation".to_string(),
        },
    ));
    assert_eq!(stale_completion.status, CommandStatus::Rejected);
    assert_eq!(
        stale_completion.violations,
        vec!["block completion object block request generation is missing".to_string()]
    );

    graph.ensure_task(21, FrontendKind::Supervisor, "b21-stale-wait-owner");
    graph.record_wait_created_with_details(
        1841,
        Some(21),
        None,
        None,
        SemanticWaitKind::DriverCompletion,
        1,
        vec![ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1828, 2)],
        None,
        RestartPolicy::InternalOnly,
        Some("b21 stale wait probe".to_string()),
    );
    let stale_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b21-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1842,
            wait: 1841,
            wait_generation: 1,
            block_request: 1828,
            block_request_generation: 2,
            note: "b21 stale block wait generation".to_string(),
        },
    ));
    assert_eq!(stale_wait.status, CommandStatus::Rejected);
    assert_eq!(
        stale_wait.violations,
        vec!["block wait request generation is missing or not submitted".to_string()]
    );
    graph.record_wait_cancelled_with_reason(1841, 125, WaitCancelReason::GenerationMismatch);

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b21-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1843,
            backend,
            block_request: 1828,
            block_request_generation: 2,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
            note: "b21 stale dma request generation".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block dma buffer request generation is missing".to_string()]
    );

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b21-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1844,
            backend,
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::pending(1828, 2)],
            note: "b21 stale queue request generation".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["block request queue request generation is missing".to_string()]
    );

    let audit = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 1,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 stale request generation audit".to_string(),
        },
    ));
    assert_eq!(audit.status, CommandStatus::Applied, "{audit:?}");
    assert_eq!(graph.block_request_generation_audit_count(), 1);
    let audit = &graph.block_request_generation_audits()[0];
    assert_eq!(
        audit.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestGenerationAudit, 1845, 1)
    );
    assert_eq!(audit.block_request, 1828);
    assert_eq!(audit.block_request_generation, 1);
    assert_eq!(audit.backend, backend);
    assert_eq!(audit.dma_buffer, dma_buffer);
    assert_eq!(audit.rejected_completion_generation_probes, 1);
    assert_eq!(audit.rejected_wait_generation_probes, 1);
    assert_eq!(audit.rejected_dma_generation_probes, 1);
    assert_eq!(audit.rejected_queue_generation_probes, 1);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("BlockRequestGenerationAuditRecorded audit=1845")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b21_rejects_missing_probe_counts_and_stale_audit_refs() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let dma_buffer = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1);

    let missing_probe = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 1,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 0,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 missing wait probe".to_string(),
        },
    ));
    assert_eq!(missing_probe.status, CommandStatus::Rejected);
    assert_eq!(
        missing_probe.violations,
        vec!["block request generation audit requires rejected probes for all paths".to_string()]
    );

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        7,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 2,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 stale audit request ref".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);
    assert_eq!(
        stale_request.violations,
        vec![
            "block request generation audit request generation is missing or inactive".to_string()
        ]
    );
}

#[test]
pub(super) fn block_runtime_b21_invariants_reject_stale_audit_request_generation() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    assert!(graph.record_block_request_generation_audit_with_id(
        1845,
        1824,
        1,
        1825,
        1,
        1828,
        1,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1),
        1,
        1,
        1,
        1,
        "b21 generation audit",
    ));
    graph.corrupt_block_request_generation_audit_request_generation_for_test(1845, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
            audit: 1845,
            target: ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1828, 2),
        })
    );
}

pub(super) fn setup_b22_disk_benchmark_graph() -> SemanticGraph {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let read_digest = SemanticGraph::expected_block_read_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        1,
        4096,
    );
    let write_digest = SemanticGraph::expected_block_write_payload_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        2,
        4096,
    );
    assert!(graph.record_block_read_path_with_id(
        1846,
        backend,
        1826,
        1,
        1827,
        1,
        read_digest,
        "b22 benchmark read path",
    ));
    assert!(graph.record_block_write_path_with_id(
        1847,
        backend,
        1828,
        1,
        1830,
        1,
        write_digest,
        "b22 benchmark write path",
    ));
    assert!(graph.record_block_request_queue_with_id(
        1848,
        backend,
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::completed(1828, 1, 1830, 1),
        ],
        "b22 benchmark completed queue",
    ));
    assert!(graph.record_block_dma_buffer_with_id(
        1849,
        backend,
        1828,
        1,
        1833,
        1,
        b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
        "b22 benchmark dma-backed write",
    ));
    graph
}

#[test]
pub(super) fn block_runtime_b22_disk_benchmark_records_iops_latency_evidence() {
    let mut graph = setup_b22_disk_benchmark_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1850,
            scenario: "fake block read/write benchmark".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 1,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 disk benchmark".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.block_benchmark_count(), 1);
    let benchmark = &graph.block_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockBenchmark, 1850, 1)
    );
    assert_eq!(benchmark.backend, backend);
    assert_eq!(benchmark.read_path, 1846);
    assert_eq!(benchmark.write_path, 1847);
    assert_eq!(benchmark.request_queue, 1848);
    assert_eq!(benchmark.block_dma_buffer, 1849);
    assert_eq!(benchmark.sample_requests, 2);
    assert_eq!(benchmark.sample_bytes, 8192);
    assert_eq!(benchmark.iops, 50_000);
    assert_eq!(benchmark.throughput_bytes_per_sec, 204_800_000);
    assert_eq!(benchmark.p50_latency_nanos, 18_000);
    assert_eq!(benchmark.p99_latency_nanos, 35_000);
    assert!(
        graph.event_log_tail(1)[0].kind.summary().contains("BlockBenchmarkRecorded benchmark=1850")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b22_rejects_stale_refs_and_invalid_metrics() {
    let mut graph = setup_b22_disk_benchmark_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let stale_read_path = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1850,
            scenario: "stale read path".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 2,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 stale read path".to_string(),
        },
    ));
    assert_eq!(stale_read_path.status, CommandStatus::Rejected);
    assert_eq!(
        stale_read_path.violations,
        vec!["block benchmark read path generation is missing or inactive".to_string()]
    );

    let over_budget = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1851,
            scenario: "over budget".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 1,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 90_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 over budget".to_string(),
        },
    ));
    assert_eq!(over_budget.status, CommandStatus::Rejected);
    assert_eq!(over_budget.violations, vec!["block benchmark exceeds latency budget".to_string()]);
}

#[test]
pub(super) fn block_runtime_b22_invariants_reject_iops_metric_drift() {
    let mut graph = setup_b22_disk_benchmark_graph();
    assert!(graph.record_block_benchmark_with_id(
        1850,
        "b22 benchmark",
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        1825,
        1,
        1846,
        1,
        1847,
        1,
        1848,
        1,
        1849,
        1,
        2,
        8192,
        1,
        1,
        2,
        40_000,
        80_000,
        18_000,
        35_000,
        "b22 invariant benchmark",
    ));
    graph.corrupt_block_benchmark_iops_for_test(1850, 50_001);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockBenchmarkInvalid { benchmark: 1850 })
    );
}

pub(super) fn setup_b23_disk_recovery_benchmark_graph() -> SemanticGraph {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let cleanup = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b23-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1888,
            io_cleanup: 1889,
            block_device: 1791,
            block_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b23 cleanup disk driver".to_string(),
        },
    ));
    assert_eq!(cleanup.status, CommandStatus::Applied);
    graph
}

#[test]
pub(super) fn block_runtime_b23_disk_recovery_benchmark_records_cleanup_latency_evidence() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1852,
            scenario: "disk driver recovery benchmark".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23 disk recovery benchmark".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.block_recovery_benchmark_count(), 1);
    let benchmark = &graph.block_recovery_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRecoveryBenchmark, 1852, 1)
    );
    assert_eq!(benchmark.cleanup, cleanup.id);
    assert_eq!(benchmark.cleanup_generation, cleanup.generation);
    assert_eq!(benchmark.backend, cleanup.backend);
    assert_eq!(benchmark.block_device, cleanup.block_device);
    assert_eq!(benchmark.driver_store, cleanup.driver_store);
    assert_eq!(benchmark.cancelled_block_waits, 1);
    assert_eq!(benchmark.cancelled_wait_tokens, 1);
    assert_eq!(benchmark.released_dma_buffers, 1);
    assert_eq!(benchmark.revoked_device_capabilities, 1);
    assert_eq!(benchmark.recovery_nanos, 70_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("BlockRecoveryBenchmarkRecorded benchmark=1852")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn block_runtime_b23_rejects_stale_cleanup_and_budget_overrun() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    let stale_cleanup = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1852,
            scenario: "stale cleanup".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation + 1,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23 stale cleanup".to_string(),
        },
    ));
    assert_eq!(stale_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cleanup.violations,
        vec!["block recovery benchmark cleanup generation is missing or incomplete".to_string()]
    );

    let over_budget = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1853,
            scenario: "over budget".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 160_000,
            budget_nanos: 150_000,
            note: "b23 over budget".to_string(),
        },
    ));
    assert_eq!(over_budget.status, CommandStatus::Rejected);
    assert_eq!(
        over_budget.violations,
        vec!["block recovery benchmark exceeds recovery budget".to_string()]
    );
}

#[test]
pub(super) fn block_runtime_b23_invariants_reject_cleanup_generation_leak() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    assert!(graph.record_block_recovery_benchmark_with_id(
        1852,
        "b23 recovery benchmark",
        cleanup.id,
        cleanup.generation,
        cleanup.io_cleanup,
        cleanup.io_cleanup_generation,
        cleanup.started_at_event,
        completed_at_event,
        cleanup.cancelled_block_waits.len() as u32,
        cleanup.cancelled_wait_tokens.len() as u32,
        cleanup.released_dma_buffers.len() as u32,
        cleanup.revoked_device_capabilities.len() as u32,
        70_000,
        150_000,
        "b23 invariant benchmark",
    ));
    graph.corrupt_block_recovery_benchmark_cleanup_generation_for_test(1852, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRecoveryBenchmarkMissingTarget {
            benchmark: 1852,
            target: ContractObjectRef::new(ContractObjectKind::BlockDriverCleanup, 1888, 2),
        })
    );
}

#[test]
pub(super) fn block_filesystem_convergence_d5_preserves_capability_wait_policy_and_cleanup_evidence()
 {
    let mut fs_graph = setup_b18_fs_wait_graph();
    let store = fs_graph.store_id("linux_syscall").unwrap();
    {
        let cache =
            fs_graph.buffer_cache_objects().iter().find(|record| record.id == 1840).unwrap();
        assert_eq!(cache.block_device, 1824);
        assert_eq!(cache.block_range, 1825);
        assert_eq!(cache.page, b11_page(1903));
        assert_eq!(cache.cache_state, BufferCacheObjectState::Dirty);
        let file = fs_graph.file_objects().iter().find(|record| record.id == 1845).unwrap();
        assert_eq!(file.buffer_cache_object, 1840);
        assert_eq!(file.path, "/demo/file.txt");
        assert_eq!(file.content_digest, 0xB13);
        let directory =
            fs_graph.directory_objects().iter().find(|record| record.id == 1850).unwrap();
        assert_eq!(directory.file_object, 1845);
        assert_eq!(directory.child_path, "/demo/file.txt");
        let gate =
            fs_graph.file_handle_capabilities().iter().find(|record| record.id == 1865).unwrap();
        assert_eq!(gate.owner_store, store);
        assert_eq!(gate.file_object, 1845);
        assert_eq!(gate.directory_object, 1850);
        assert_ne!(gate.capability_generation, 0);
        assert_ne!(gate.handle_generation, 0);
        assert_eq!(gate.operation, "read");
        assert_eq!(gate.state, FileHandleCapabilityState::Allowed);
        assert_ne!(gate.recorded_at_event, 0);
        let cap_record = fs_graph.capabilities().record(gate.capability).unwrap();
        assert_eq!(
            cap_record.object_ref,
            Some(AuthorityObjectRef::internal(
                CapabilityClass::FileHandle,
                ContractObjectRef::new(ContractObjectKind::FileObject, 1845, 1),
            ))
        );
    }

    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    for (command_id, command) in [
        (
            501,
            SemanticCommand::CreateWait {
                wait: 1910,
                owner_task: None,
                owner_store: Some(store),
                owner_store_generation: Some(1),
                kind: SemanticWaitKind::FdReadable,
                generation: 1,
                blockers: vec![blocker],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("d5 cancellable filesystem wait".to_string()),
            },
        ),
        (
            502,
            SemanticCommand::RecordFsWait {
                fs_wait: 1911,
                wait: 1910,
                wait_generation: 1,
                file_handle_capability: 1865,
                file_handle_capability_generation: 1,
                operation: "read".to_string(),
                sequence: 3,
                note: "d5 fs wait uses file handle capability blocker".to_string(),
            },
        ),
        (
            503,
            SemanticCommand::CancelFsWait {
                fs_wait: 1911,
                fs_wait_generation: 1,
                errno: 9,
                reason: WaitCancelReason::CloseFd,
                note: "d5 close fd cancels filesystem wait token".to_string(),
            },
        ),
    ] {
        let result = fs_graph.apply_envelope(CommandEnvelope::new(command_id, "d5-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }
    let fs_wait = fs_graph.fs_waits().iter().find(|record| record.id == 1911).unwrap();
    assert_eq!(fs_wait.blocker, blocker);
    assert_eq!(fs_wait.state, FsWaitState::Cancelled);
    assert_eq!(fs_wait.cancel_reason, Some(WaitCancelReason::CloseFd));
    assert!(fs_wait.completed_at_event.is_some());
    assert_eq!(
        fs_graph.wait_records().iter().find(|record| record.id == 1910).unwrap().state,
        WaitState::Cancelled
    );
    assert!(
        fs_graph
            .event_log_tail(8)
            .iter()
            .any(|event| { event.kind.summary().contains("FsWaitCancelled fs_wait=1911") })
    );
    assert!(fs_graph.check_invariants().is_ok());

    let mut policy_graph = setup_b20_pending_io_policy_graph();
    let mut policy_result_events = Vec::new();
    for command in [
        CommandEnvelope::new(
            504,
            "d5-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1892,
                block_wait: 1884,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Retry,
                retry_request: Some(1891),
                retry_request_generation: Some(1),
                errno: 11,
                retry_attempt: 1,
                max_retries: 2,
                note: "d5 retry pending block io".to_string(),
            },
        ),
        CommandEnvelope::new(
            505,
            "d5-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1899,
                block_wait: 1895,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Eio,
                retry_request: None,
                retry_request_generation: None,
                errno: 5,
                retry_attempt: 0,
                max_retries: 0,
                note: "d5 return eio for pending block io".to_string(),
            },
        ),
        CommandEnvelope::new(
            506,
            "d5-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1900,
                block_wait: 1898,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Cancel,
                retry_request: None,
                retry_request_generation: None,
                errno: 125,
                retry_attempt: 0,
                max_retries: 0,
                note: "d5 cancel pending block io".to_string(),
            },
        ),
    ] {
        let result = policy_graph.apply_envelope(command);
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
        assert!(!result.events.is_empty(), "policy command must be event-visible");
        policy_result_events.extend(result.events);
    }
    assert_eq!(policy_graph.block_pending_io_policy_count(), 3);
    assert_eq!(policy_result_events.len(), 9);
    let retry =
        policy_graph.block_pending_io_policies().iter().find(|record| record.id == 1892).unwrap();
    assert_eq!(retry.action, BlockPendingIoAction::Retry);
    assert_eq!(retry.retry_request, Some(1891));
    assert_eq!(retry.state, BlockPendingIoPolicyState::RetryScheduled);
    assert_ne!(retry.recorded_at_event, 0);
    let eio =
        policy_graph.block_pending_io_policies().iter().find(|record| record.id == 1899).unwrap();
    assert_eq!(eio.action, BlockPendingIoAction::Eio);
    assert_eq!(eio.state, BlockPendingIoPolicyState::EioReturned);
    assert_ne!(eio.recorded_at_event, 0);
    let cancel =
        policy_graph.block_pending_io_policies().iter().find(|record| record.id == 1900).unwrap();
    assert_eq!(cancel.action, BlockPendingIoAction::Cancel);
    assert_eq!(cancel.state, BlockPendingIoPolicyState::Cancelled);
    assert_ne!(cancel.recorded_at_event, 0);
    for (block_wait, reason) in [
        (1884, WaitCancelReason::DeviceFault),
        (1895, WaitCancelReason::DeviceFault),
        (1898, WaitCancelReason::ResourceDropped),
    ] {
        let wait =
            policy_graph.block_waits().iter().find(|record| record.id == block_wait).unwrap();
        assert_eq!(wait.state, BlockWaitState::Cancelled);
        assert_eq!(wait.cancel_reason, Some(reason));
        let token =
            policy_graph.wait_records().iter().find(|record| record.id == wait.wait).unwrap();
        assert_eq!(token.state, WaitState::Cancelled);
    }
    let policy_event_summaries: Vec<_> = policy_graph
        .event_log_tail(16)
        .iter()
        .map(|event| event.kind.summary())
        .filter(|summary| summary.starts_with("BlockPendingIoPolicyApplied "))
        .collect();
    assert_eq!(policy_event_summaries.len(), 3);
    assert!(policy_event_summaries.iter().any(|summary| summary.contains("action=retry")));
    assert!(policy_event_summaries.iter().any(|summary| summary.contains("action=eio")));
    assert!(policy_event_summaries.iter().any(|summary| summary.contains("action=cancel")));
    assert!(policy_graph.check_invariants().is_ok());

    let cleanup_graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup =
        cleanup_graph.block_driver_cleanups().iter().find(|record| record.id == 1888).unwrap();
    assert_eq!(cleanup.state, BlockDriverCleanupState::Completed);
    assert_eq!(cleanup.cancelled_block_waits.len(), 1);
    assert_eq!(cleanup.cancelled_wait_tokens.len(), 1);
    assert_eq!(cleanup.released_dma_buffers.len(), 1);
    assert_eq!(cleanup.revoked_device_capabilities.len(), 1);
    assert!(cleanup.completed_at_event.unwrap() > cleanup.started_at_event);
    let io_cleanup =
        cleanup_graph.io_cleanups().iter().find(|record| record.id == cleanup.io_cleanup).unwrap();
    assert_eq!(io_cleanup.released_dma_buffers, cleanup.released_dma_buffers);
    assert_eq!(io_cleanup.revoked_device_capabilities, cleanup.revoked_device_capabilities);
    assert_eq!(
        cleanup_graph.block_waits().iter().find(|record| record.id == 1884).unwrap().state,
        BlockWaitState::Cancelled
    );
    assert_eq!(
        cleanup_graph.wait_records().iter().find(|record| record.id == 1883).unwrap().state,
        WaitState::Cancelled
    );
    assert_eq!(
        cleanup_graph.dma_buffer_objects().iter().find(|record| record.id == 1887).unwrap().state,
        DmaBufferObjectState::Released
    );
    assert!(cleanup_graph.check_invariants().is_ok());
}
