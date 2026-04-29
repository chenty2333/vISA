use super::*;

#[test]
fn semantic_roots_reject_block_read_path_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_read_path_count = 1;
    package.semantic.block_read_paths.push(artifact_manifest::BlockReadPathManifest {
        id: 58,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        data_digest: 1,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 74,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block read path root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_write_path_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_write_path_count = 1;
    package.semantic.block_write_paths.push(artifact_manifest::BlockWritePathManifest {
        id: 59,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        sequence: 2,
        completed_bytes: 4096,
        payload_digest: 1,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 75,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block write path root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_queue_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_queue_count = 1;
    package.semantic.block_request_queues.push(artifact_manifest::BlockRequestQueueManifest {
        id: 60,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        depth: 4,
        entries: vec![artifact_manifest::BlockRequestQueueEntryManifest {
            request: 53,
            request_generation: 1,
            completion: Some(54),
            completion_generation: Some(1),
            sequence: 2,
            operation: "write".to_owned(),
            byte_len: 4096,
            state: "completed".to_owned(),
        }],
        pending_count: 0,
        completed_count: 1,
        first_sequence: 2,
        last_sequence: 2,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 76,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request queue root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_dma_buffer_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_dma_buffer_count = 1;
    package.semantic.block_dma_buffers.push(artifact_manifest::BlockDmaBufferManifest {
        id: 61,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        dma_buffer: 20,
        dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        descriptor: 19,
        descriptor_generation: 1,
        queue: 18,
        queue_generation: 1,
        operation: "write".to_owned(),
        access: "read-write".to_owned(),
        byte_len: 4096,
        buffer_len: 4096,
        buffer_digest: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 77,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block dma buffer root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_page_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_page_object_count = 1;
    package.semantic.block_page_objects.push(artifact_manifest::BlockPageObjectManifest {
        id: 62,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        dma_buffer: 20,
        dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        aspace: artifact_manifest::ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 70,
            generation: 1,
        },
        vma_region: artifact_manifest::ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 71,
            generation: 1,
        },
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        page_backing: "file-backed".to_owned(),
        cow_state: "none".to_owned(),
        page_state: "live".to_owned(),
        page_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        generation: 1,
        state: "integrated".to_owned(),
        recorded_at_event: 78,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block page object root/count mismatch");
}

#[test]
fn semantic_roots_reject_buffer_cache_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.buffer_cache_object_count = 1;
    package.semantic.buffer_cache_objects.push(artifact_manifest::BufferCacheObjectManifest {
        id: 63,
        block_page_object: 62,
        block_page_object_generation: 1,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        aspace: artifact_manifest::ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 70,
            generation: 1,
        },
        vma_region: artifact_manifest::ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 71,
            generation: 1,
        },
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        page_offset: 0,
        block_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        cache_state: "dirty".to_owned(),
        coherency_epoch: 1,
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 79,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "buffer cache object root/count mismatch");
}

#[test]
fn semantic_roots_reject_file_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.file_object_count = 1;
    package.semantic.file_objects.push(artifact_manifest::FileObjectManifest {
        id: 64,
        buffer_cache_object: 63,
        buffer_cache_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        namespace: "rootfs".to_owned(),
        file_key: "demo-file".to_owned(),
        path: "/demo/file.txt".to_owned(),
        file_offset: 0,
        byte_len: 4096,
        file_size: 4096,
        content_digest: 1,
        cache_state: "dirty".to_owned(),
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 80,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "file object root/count mismatch");
}

#[test]
fn semantic_roots_reject_directory_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.directory_object_count = 1;
    package.semantic.directory_objects.push(artifact_manifest::DirectoryObjectManifest {
        id: 65,
        file_object: 64,
        file_object_generation: 1,
        namespace: "rootfs".to_owned(),
        directory_key: "demo-dir".to_owned(),
        directory_path: "/demo".to_owned(),
        entry_name: "file.txt".to_owned(),
        child_file_key: "demo-file".to_owned(),
        child_path: "/demo/file.txt".to_owned(),
        entry_kind: "file".to_owned(),
        file_size: 4096,
        content_digest: 1,
        generation: 1,
        state: "cached".to_owned(),
        recorded_at_event: 81,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "directory object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fat_adapter_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fat_adapter_object_count = 1;
    package.semantic.fat_adapter_objects.push(artifact_manifest::FatAdapterObjectManifest {
        id: 66,
        directory_object: 65,
        directory_object_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        implementation: "fatfs".to_owned(),
        version: "0.3.6".to_owned(),
        profile: "fatfs-read-write-demo-v1".to_owned(),
        volume_label: "VMOSFAT".to_owned(),
        image_bytes: 1_048_576,
        adapter_path: "DEMO.TXT".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_written: 32,
        bytes_read: 32,
        write_digest: 1,
        read_digest: 1,
        file_content_digest: 1,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 82,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fat adapter object root/count mismatch");
}

#[test]
fn semantic_roots_reject_ext4_adapter_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.ext4_adapter_object_count = 1;
    package.semantic.ext4_adapter_objects.push(artifact_manifest::Ext4AdapterObjectManifest {
        id: 67,
        directory_object: 65,
        directory_object_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        implementation: "ext4-view".to_owned(),
        version: "0.9.3".to_owned(),
        profile: "ext4-read-only-demo-v1".to_owned(),
        volume_label: "VMOSEXT4".to_owned(),
        image_bytes: 32_768,
        adapter_path: "/demo.txt".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_read: 32,
        read_digest: 1,
        file_content_digest: 1,
        directory_entries: 1,
        read_only_enforced: true,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 83,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "ext4 adapter object root/count mismatch");
}

#[test]
fn semantic_roots_reject_file_handle_capability_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.file_handle_capability_count = 1;
    package.semantic.file_handle_capabilities.push(
        artifact_manifest::FileHandleCapabilityManifest {
            id: 68,
            owner_store: 7,
            owner_store_generation: 1,
            file_object: 64,
            file_object_generation: 1,
            directory_object: 65,
            directory_object_generation: 1,
            capability: 9,
            capability_generation: 1,
            handle_slot: 1,
            handle_generation: 1,
            handle_tag: 123,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 32,
            content_digest: 1,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 84,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "file handle capability root/count mismatch");
}

#[test]
fn semantic_roots_reject_fs_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fs_wait_count = 1;
    package.semantic.fs_waits.push(artifact_manifest::FsWaitManifest {
        id: 69,
        wait: 70,
        wait_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        directory_object: 65,
        directory_object_generation: 1,
        file_handle_capability: 68,
        file_handle_capability_generation: 1,
        operation: "read".to_owned(),
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "file-handle-capability".to_owned(),
            id: 68,
            generation: 1,
        },
        sequence: 1,
        byte_len: 32,
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 85,
        completed_at_event: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fs wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_driver_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_driver_cleanup_count = 1;
    package.semantic.block_driver_cleanups.push(artifact_manifest::BlockDriverCleanupManifest {
        id: 70,
        io_cleanup: 71,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 1,
        device: 72,
        device_generation: 1,
        driver_binding: 73,
        driver_binding_generation: 1,
        block_device: 74,
        block_device_generation: 1,
        backend: artifact_manifest::ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 75,
            generation: 1,
        },
        cancelled_block_waits: vec![artifact_manifest::ContractObjectRefManifest {
            kind: "block-wait".to_owned(),
            id: 76,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![artifact_manifest::ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 77,
            generation: 1,
        }],
        revoked_device_capabilities: Vec::new(),
        released_dma_buffers: Vec::new(),
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 86,
        completed_at_event: Some(87),
        reason: "device-fault".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block driver cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_pending_io_policy_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_pending_io_policy_count = 1;
    package.semantic.block_pending_io_policies.push(
        artifact_manifest::BlockPendingIoPolicyManifest {
            id: 71,
            block_wait: 72,
            block_wait_generation: 1,
            wait: 73,
            wait_generation: 1,
            block_request: 74,
            block_request_generation: 1,
            retry_request: Some(75),
            retry_request_generation: Some(1),
            block_device: 76,
            block_device_generation: 1,
            block_range: 77,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 1,
            byte_len: 4096,
            action: "retry".to_owned(),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            generation: 1,
            state: "retry-scheduled".to_owned(),
            recorded_at_event: 88,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block pending io policy root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_generation_audit_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_generation_audit_count = 1;
    package.semantic.block_request_generation_audits.push(
        artifact_manifest::BlockRequestGenerationAuditManifest {
            id: 78,
            block_device: 76,
            block_device_generation: 1,
            block_range: 77,
            block_range_generation: 1,
            block_request: 74,
            block_request_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "fake-block-backend-object".to_owned(),
                id: 79,
                generation: 1,
            },
            dma_buffer: artifact_manifest::ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 80,
                generation: 1,
            },
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 89,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request generation audit root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_benchmark_count = 1;
    package.semantic.block_benchmarks.push(artifact_manifest::BlockBenchmarkManifest {
        id: 79,
        scenario: "test".to_owned(),
        backend: artifact_manifest::ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 80,
            generation: 1,
        },
        block_device: 76,
        block_device_generation: 1,
        block_range: 77,
        block_range_generation: 1,
        read_path: 81,
        read_path_generation: 1,
        write_path: 82,
        write_path_generation: 1,
        request_queue: 83,
        request_queue_generation: 1,
        block_dma_buffer: 84,
        block_dma_buffer_generation: 1,
        sample_requests: 2,
        sample_bytes: 8192,
        read_completed_requests: 1,
        write_completed_requests: 1,
        queue_completed_requests: 2,
        measured_nanos: 1000,
        budget_nanos: 2000,
        iops: 2_000_000,
        throughput_bytes_per_sec: 8_192_000_000,
        p50_latency_nanos: 400,
        p99_latency_nanos: 900,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 90,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_recovery_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_recovery_benchmark_count = 1;
    package.semantic.block_recovery_benchmarks.push(
        artifact_manifest::BlockRecoveryBenchmarkManifest {
            id: 85,
            scenario: "test".to_owned(),
            cleanup: 86,
            cleanup_generation: 1,
            io_cleanup: 87,
            io_cleanup_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-blk-backend-object".to_owned(),
                id: 88,
                generation: 1,
            },
            block_device: 89,
            block_device_generation: 1,
            driver_store: 90,
            driver_store_generation: 1,
            device: 91,
            device_generation: 1,
            driver_binding: 92,
            driver_binding_generation: 1,
            recovery_start_event: 93,
            recovery_complete_event: 94,
            cancelled_block_waits: 1,
            cancelled_wait_tokens: 1,
            released_dma_buffers: 1,
            revoked_device_capabilities: 1,
            recovery_nanos: 1000,
            budget_nanos: 2000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 95,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block recovery benchmark root/count mismatch");
}
