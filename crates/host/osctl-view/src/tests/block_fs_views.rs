use super::*;

#[test]
fn block_device_view_v1_exposes_device_and_sector_contract() {
    let view = block_device_object_view_v1(&BlockDeviceObjectManifest {
        id: 104,
        name: "blk0".to_owned(),
        device: 35,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 104,
        note: "block device".to_owned(),
    });
    assert_eq!(view["kind"], "block-device");
    assert_eq!(view["owner"]["device"]["kind"], "device");
    assert_eq!(view["references"]["device"]["generation"], 1);
    assert_eq!(view["identity"]["name"], "blk0");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["sector_count"], 4096);
    assert_eq!(view["contract"]["read_only"], false);
    assert_eq!(view["contract"]["max_transfer_sectors"], 128);
    assert_eq!(view["last_transition"]["recorded_at_event"], 104);
}

#[test]
fn block_range_view_v1_exposes_sector_and_byte_ranges() {
    let view = block_range_object_view_v1(&BlockRangeObjectManifest {
        id: 105,
        block_device: 104,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 105,
        note: "block range".to_owned(),
    });
    assert_eq!(view["kind"], "block-range");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["sector_range"]["start_sector"], 64);
    assert_eq!(view["sector_range"]["sector_count"], 8);
    assert_eq!(view["byte_range"]["byte_offset"], 32768);
    assert_eq!(view["byte_range"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 105);
}

#[test]
fn block_request_view_v1_exposes_range_and_operation_contract() {
    let view = block_request_object_view_v1(&BlockRequestObjectManifest {
        id: 106,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 106,
        note: "block request".to_owned(),
    });
    assert_eq!(view["kind"], "block-request");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["references"]["block_range"]["kind"], "block-range");
    assert_eq!(view["references"]["block_range"]["generation"], 1);
    assert_eq!(view["request"]["operation"], "read");
    assert_eq!(view["request"]["sequence"], 1);
    assert_eq!(view["request"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 106);
}

#[test]
fn block_completion_view_v1_exposes_request_and_result_contract() {
    let view = block_completion_object_view_v1(&BlockCompletionObjectManifest {
        id: 107,
        block_request: 106,
        block_request_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        status: "success".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 107,
        note: "block completion".to_owned(),
    });
    assert_eq!(view["kind"], "block-completion");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["block_range"]["kind"], "block-range");
    assert_eq!(view["completion"]["sequence"], 1);
    assert_eq!(view["completion"]["completed_bytes"], 4096);
    assert_eq!(view["completion"]["status"], "success");
    assert_eq!(view["last_transition"]["recorded_at_event"], 107);
}

#[test]
fn block_wait_view_v1_exposes_wait_token_and_completion_contract() {
    let view = block_wait_view_v1(&BlockWaitManifest {
        id: 108,
        wait: 109,
        wait_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 108,
        completed_at_event: Some(110),
        completion: Some(107),
        completion_generation: Some(1),
        cancel_reason: None,
        note: "block wait".to_owned(),
    });
    assert_eq!(view["kind"], "block-wait");
    assert_eq!(view["owner"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["completion"]["kind"], "block-completion");
    assert_eq!(view["wait"]["operation"], "read");
    assert_eq!(view["wait"]["sequence"], 1);
    assert_eq!(view["wait"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["completed_at_event"], 110);
}

#[test]
fn fake_block_backend_view_v1_exposes_block_device_and_profile_contract() {
    let view = fake_block_backend_object_view_v1(&FakeBlockBackendObjectManifest {
        id: 111,
        name: "fake-block0".to_owned(),
        block_device: 104,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 0x766d_6f73_626c_6b31,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 111,
        note: "fake block backend".to_owned(),
    });
    assert_eq!(view["kind"], "fake-block-backend");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["owner"]["block_device"]["generation"], 1);
    assert_eq!(view["identity"]["provider"], "service_core");
    assert_eq!(view["identity"]["profile"], "fake-block-v1");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["sector_count"], 4096);
    assert_eq!(view["contract"]["max_transfer_sectors"], 128);
    assert_eq!(view["last_transition"]["recorded_at_event"], 111);
}

#[test]
fn virtio_blk_backend_view_v1_exposes_driver_binding_and_profile_contract() {
    let view = virtio_blk_backend_object_view_v1(&VirtioBlkBackendObjectManifest {
        id: 112,
        name: "virtio-blk0-backend".to_owned(),
        block_device: 104,
        block_device_generation: 1,
        driver_binding: 130,
        driver_binding_generation: 1,
        device: 35,
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
        recorded_at_event: 112,
        note: "virtio block backend".to_owned(),
    });
    assert_eq!(view["kind"], "virtio-blk-backend");
    assert_eq!(view["owner"]["block_device"]["kind"], "block-device");
    assert_eq!(view["owner"]["driver_binding"]["kind"], "driver-store-binding");
    assert_eq!(view["references"]["device"]["kind"], "device");
    assert_eq!(view["identity"]["provider"], "substrate_virtio");
    assert_eq!(view["identity"]["profile"], "virtio-blk-backend-skeleton-v1");
    assert_eq!(view["identity"]["model"], "virtio-blk");
    assert_eq!(view["contract"]["sector_size"], 512);
    assert_eq!(view["contract"]["queue_size"], 8);
    assert_eq!(view["contract"]["irq_vector"], 6);
    assert_eq!(view["last_transition"]["recorded_at_event"], 112);
}

#[test]
fn block_read_path_view_v1_exposes_backend_request_completion_and_digest() {
    let view = block_read_path_view_v1(&BlockReadPathManifest {
        id: 113,
        backend_kind: "fake-block-backend".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_completion: 107,
        block_completion_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        data_digest: 0xfeed,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 113,
        note: "block read path".to_owned(),
    });
    assert_eq!(view["kind"], "block-read-path");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["block_completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["read"]["completed_bytes"], 4096);
    assert_eq!(view["read"]["data_digest"], 0xfeed);
    assert_eq!(view["last_transition"]["recorded_at_event"], 113);
}

#[test]
fn block_write_path_view_v1_exposes_backend_request_completion_and_payload_digest() {
    let view = block_write_path_view_v1(&BlockWritePathManifest {
        id: 114,
        backend_kind: "fake-block-backend".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 106,
        block_request_generation: 1,
        block_completion: 107,
        block_completion_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        sequence: 2,
        completed_bytes: 4096,
        payload_digest: 0xbeef,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 114,
        note: "block write path".to_owned(),
    });
    assert_eq!(view["kind"], "block-write-path");
    assert_eq!(view["owner"]["block_request"]["kind"], "block-request");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["block_completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["write"]["completed_bytes"], 4096);
    assert_eq!(view["write"]["payload_digest"], 0xbeef);
    assert_eq!(view["last_transition"]["recorded_at_event"], 114);
}

#[test]
fn block_request_queue_view_v1_exposes_entries_depth_and_generations() {
    let view = block_request_queue_view_v1(&BlockRequestQueueManifest {
        id: 115,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        depth: 4,
        entries: vec![
            artifact_manifest::BlockRequestQueueEntryManifest {
                request: 106,
                request_generation: 1,
                completion: Some(107),
                completion_generation: Some(1),
                sequence: 1,
                operation: "read".to_owned(),
                byte_len: 4096,
                state: "completed".to_owned(),
            },
            artifact_manifest::BlockRequestQueueEntryManifest {
                request: 108,
                request_generation: 1,
                completion: None,
                completion_generation: None,
                sequence: 2,
                operation: "write".to_owned(),
                byte_len: 4096,
                state: "pending".to_owned(),
            },
        ],
        pending_count: 1,
        completed_count: 1,
        first_sequence: 1,
        last_sequence: 2,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 115,
        note: "block request queue".to_owned(),
    });
    assert_eq!(view["kind"], "block-request-queue");
    assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["references"]["entries"][0]["request"]["kind"], "block-request");
    assert_eq!(view["references"]["entries"][0]["completion"]["kind"], "block-completion");
    assert_eq!(view["references"]["entries"][1]["completion"], serde_json::Value::Null);
    assert_eq!(view["queue"]["depth"], 4);
    assert_eq!(view["queue"]["pending_count"], 1);
    assert_eq!(view["queue"]["completed_count"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 115);
}

#[test]
fn block_dma_buffer_view_v1_exposes_request_dma_and_buffer_contract() {
    let view = block_dma_buffer_view_v1(&BlockDmaBufferManifest {
        id: 116,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 111,
        backend_generation: 1,
        block_request: 108,
        block_request_generation: 1,
        dma_buffer: 210,
        dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        descriptor: 209,
        descriptor_generation: 1,
        queue: 208,
        queue_generation: 1,
        operation: "write".to_owned(),
        access: "read-write".to_owned(),
        byte_len: 4096,
        buffer_len: 4096,
        buffer_digest: 0xb10,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 116,
        note: "block dma buffer".to_owned(),
    });
    assert_eq!(view["kind"], "block-dma-buffer");
    assert_eq!(view["owner"]["backend"]["kind"], "fake-block-backend");
    assert_eq!(view["owner"]["block_request"]["generation"], 1);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer");
    assert_eq!(view["references"]["descriptor"]["id"], 209);
    assert_eq!(view["references"]["queue"]["generation"], 1);
    assert_eq!(view["buffer"]["operation"], "write");
    assert_eq!(view["buffer"]["buffer_digest"], 0xb10);
    assert_eq!(view["last_transition"]["dma_buffer_generation"], 1);
}

#[test]
fn block_page_object_view_v1_exposes_page_and_block_dma_contract() {
    let view = block_page_object_view_v1(&BlockPageObjectManifest {
        id: 117,
        block_dma_buffer: 116,
        block_dma_buffer_generation: 1,
        block_request: 108,
        block_request_generation: 1,
        block_completion: 109,
        block_completion_generation: 1,
        dma_buffer: 210,
        dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        aspace: ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 301,
            generation: 1,
        },
        vma_region: ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 302,
            generation: 1,
        },
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        page_backing: "file-backed".to_owned(),
        cow_state: "none".to_owned(),
        page_state: "live".to_owned(),
        page_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        generation: 1,
        state: "integrated".to_owned(),
        recorded_at_event: 117,
        note: "block page object".to_owned(),
    });
    assert_eq!(view["kind"], "block-page-object");
    assert_eq!(view["owner"]["page"]["kind"], "page-object");
    assert_eq!(view["owner"]["block_dma_buffer"]["kind"], "block-dma-buffer");
    assert_eq!(view["references"]["aspace"]["id"], 301);
    assert_eq!(view["references"]["vma_region"]["generation"], 1);
    assert_eq!(view["references"]["block_completion"]["id"], 109);
    assert_eq!(view["page"]["dirty_generation"], 2);
    assert_eq!(view["page"]["backing"], "file-backed");
    assert_eq!(view["page"]["byte_len"], 4096);
    assert_eq!(view["last_transition"]["recorded_at_event"], 117);
}

#[test]
fn buffer_cache_object_view_v1_exposes_page_and_block_range_contract() {
    let view = buffer_cache_object_view_v1(&BufferCacheObjectManifest {
        id: 118,
        block_page_object: 117,
        block_page_object_generation: 1,
        block_dma_buffer: 116,
        block_dma_buffer_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        aspace: ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 301,
            generation: 1,
        },
        vma_region: ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 302,
            generation: 1,
        },
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        page_offset: 0,
        block_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        cache_state: "dirty".to_owned(),
        coherency_epoch: 7,
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 118,
        note: "buffer cache object".to_owned(),
    });
    assert_eq!(view["kind"], "buffer-cache-object");
    assert_eq!(view["owner"]["page"]["kind"], "page-object");
    assert_eq!(view["owner"]["block_range"]["kind"], "block-range");
    assert_eq!(view["references"]["block_page_object"]["kind"], "block-page-object");
    assert_eq!(view["references"]["block_dma_buffer"]["generation"], 1);
    assert_eq!(view["references"]["aspace"]["id"], 301);
    assert_eq!(view["cache"]["page_dirty_generation"], 2);
    assert_eq!(view["cache"]["cache_state"], "dirty");
    assert_eq!(view["cache"]["coherency_epoch"], 7);
    assert_eq!(view["last_transition"]["recorded_at_event"], 118);
}

#[test]
fn file_object_view_v1_exposes_cache_file_and_page_contract() {
    let view = file_object_view_v1(&FileObjectManifest {
        id: 119,
        buffer_cache_object: 118,
        buffer_cache_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        block_range: 105,
        block_range_generation: 1,
        page: ContractObjectRefManifest { kind: "page-object".to_owned(), id: 303, generation: 1 },
        page_dirty_generation: 2,
        namespace: "rootfs".to_owned(),
        file_key: "demo-file".to_owned(),
        path: "/demo/file.txt".to_owned(),
        file_offset: 0,
        byte_len: 4096,
        file_size: 4096,
        content_digest: 0xB13,
        cache_state: "dirty".to_owned(),
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 119,
        note: "file object".to_owned(),
    });
    assert_eq!(view["kind"], "file-object");
    assert_eq!(view["owner"]["namespace"], "rootfs");
    assert_eq!(view["owner"]["file_key"], "demo-file");
    assert_eq!(view["references"]["buffer_cache_object"]["kind"], "buffer-cache-object");
    assert_eq!(view["references"]["block_range"]["generation"], 1);
    assert_eq!(view["references"]["page"]["id"], 303);
    assert_eq!(view["file"]["content_digest"], 0xB13);
    assert_eq!(view["file"]["cache_state"], "dirty");
    assert_eq!(view["last_transition"]["recorded_at_event"], 119);
}

#[test]
fn directory_object_view_v1_exposes_file_entry_contract() {
    let view = directory_object_view_v1(&DirectoryObjectManifest {
        id: 120,
        file_object: 119,
        file_object_generation: 1,
        namespace: "rootfs".to_owned(),
        directory_key: "demo-dir".to_owned(),
        directory_path: "/demo".to_owned(),
        entry_name: "file.txt".to_owned(),
        child_file_key: "demo-file".to_owned(),
        child_path: "/demo/file.txt".to_owned(),
        entry_kind: "file".to_owned(),
        file_size: 4096,
        content_digest: 0xB13,
        generation: 1,
        state: "cached".to_owned(),
        recorded_at_event: 120,
        note: "directory object".to_owned(),
    });
    assert_eq!(view["kind"], "directory-object");
    assert_eq!(view["owner"]["namespace"], "rootfs");
    assert_eq!(view["owner"]["directory_key"], "demo-dir");
    assert_eq!(view["owner"]["entry_name"], "file.txt");
    assert_eq!(view["references"]["file_object"]["kind"], "file-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["directory"]["entry_kind"], "file");
    assert_eq!(view["directory"]["child_path"], "/demo/file.txt");
    assert_eq!(view["directory"]["content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 120);
}

#[test]
fn fat_adapter_object_view_v1_exposes_read_write_adapter_contract() {
    let view = fat_adapter_object_view_v1(&FatAdapterObjectManifest {
        id: 121,
        directory_object: 120,
        directory_object_generation: 1,
        file_object: 119,
        file_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        implementation: "fatfs".to_owned(),
        version: "0.3.6".to_owned(),
        profile: "fatfs-read-write-demo-v1".to_owned(),
        volume_label: "VISAFAT".to_owned(),
        image_bytes: 1_048_576,
        adapter_path: "DEMO.TXT".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_written: 35,
        bytes_read: 35,
        write_digest: 0x1234,
        read_digest: 0x1234,
        file_content_digest: 0xB13,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 121,
        note: "fat adapter object".to_owned(),
    });
    assert_eq!(view["kind"], "fat-adapter-object");
    assert_eq!(view["owner"]["implementation"], "fatfs");
    assert_eq!(view["owner"]["profile"], "fatfs-read-write-demo-v1");
    assert_eq!(view["references"]["directory_object"]["kind"], "directory-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["fat"]["bytes_written"], 35);
    assert_eq!(view["fat"]["read_digest"], 0x1234);
    assert_eq!(view["fat"]["file_content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 121);
}

#[test]
fn ext4_adapter_object_view_v1_exposes_read_only_adapter_contract() {
    let view = ext4_adapter_object_view_v1(&Ext4AdapterObjectManifest {
        id: 122,
        directory_object: 120,
        directory_object_generation: 1,
        file_object: 119,
        file_object_generation: 1,
        block_device: 104,
        block_device_generation: 1,
        implementation: "ext4-view".to_owned(),
        version: "0.9.3".to_owned(),
        profile: "ext4-read-only-demo-v1".to_owned(),
        volume_label: "VISAEXT4".to_owned(),
        image_bytes: 32 * 1024,
        adapter_path: "/demo.txt".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_read: 34,
        read_digest: 0x6121,
        file_content_digest: 0xB13,
        directory_entries: 1,
        read_only_enforced: true,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 122,
        note: "ext4 adapter object".to_owned(),
    });
    assert_eq!(view["kind"], "ext4-adapter-object");
    assert_eq!(view["owner"]["implementation"], "ext4-view");
    assert_eq!(view["owner"]["profile"], "ext4-read-only-demo-v1");
    assert_eq!(view["references"]["directory_object"]["kind"], "directory-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["ext4"]["bytes_read"], 34);
    assert_eq!(view["ext4"]["read_digest"], 0x6121);
    assert_eq!(view["ext4"]["file_content_digest"], 0xB13);
    assert_eq!(view["ext4"]["directory_entries"], 1);
    assert_eq!(view["ext4"]["read_only_enforced"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 122);
}

#[test]
fn file_handle_capability_view_v1_exposes_file_and_capability_gate() {
    let view = file_handle_capability_view_v1(&FileHandleCapabilityManifest {
        id: 123,
        owner_store: 7,
        owner_store_generation: 3,
        file_object: 119,
        file_object_generation: 1,
        directory_object: 120,
        directory_object_generation: 1,
        capability: 44,
        capability_generation: 5,
        handle_slot: 9,
        handle_generation: 5,
        handle_tag: 0xFEED,
        operation: "read".to_owned(),
        file_offset: 0,
        byte_len: 512,
        content_digest: 0xB13,
        generation: 1,
        state: "allowed".to_owned(),
        recorded_at_event: 123,
        note: "file handle capability".to_owned(),
    });
    assert_eq!(view["kind"], "file-handle-capability");
    assert_eq!(view["owner"]["store"]["id"], 7);
    assert_eq!(view["owner"]["operation"], "read");
    assert_eq!(view["references"]["file_object"]["kind"], "file-object");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["directory_object"]["id"], 120);
    assert_eq!(view["references"]["capability"]["generation"], 5);
    assert_eq!(view["handle"]["slot"], 9);
    assert_eq!(view["handle"]["generation"], 5);
    assert_eq!(view["handle"]["tag"], 0xFEED);
    assert_eq!(view["file_access"]["byte_len"], 512);
    assert_eq!(view["file_access"]["content_digest"], 0xB13);
    assert_eq!(view["last_transition"]["recorded_at_event"], 123);
}

#[test]
fn fs_wait_view_v1_exposes_file_handle_wait_contract() {
    let view = fs_wait_view_v1(&FsWaitManifest {
        id: 124,
        wait: 55,
        wait_generation: 1,
        owner_store: 7,
        owner_store_generation: 3,
        file_object: 119,
        file_object_generation: 1,
        directory_object: 120,
        directory_object_generation: 1,
        file_handle_capability: 123,
        file_handle_capability_generation: 1,
        operation: "read".to_owned(),
        blocker: ContractObjectRefManifest {
            kind: "file-handle-capability".to_owned(),
            id: 123,
            generation: 1,
        },
        sequence: 9,
        byte_len: 512,
        generation: 1,
        state: "cancelled".to_owned(),
        created_at_event: 124,
        completed_at_event: Some(125),
        cancel_reason: Some("close-fd".to_owned()),
        note: "fs wait".to_owned(),
    });
    assert_eq!(view["kind"], "fs-wait");
    assert_eq!(view["owner"]["store"]["id"], 7);
    assert_eq!(view["owner"]["operation"], "read");
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["file_handle_capability"]["kind"], "file-handle-capability");
    assert_eq!(view["references"]["file_object"]["id"], 119);
    assert_eq!(view["references"]["blocker"]["id"], 123);
    assert_eq!(view["wait"]["sequence"], 9);
    assert_eq!(view["wait"]["cancel_reason"], "close-fd");
    assert_eq!(view["last_error"]["cancel_reason"], "close-fd");
    assert_eq!(view["last_transition"]["completed_at_event"], 125);
}

#[test]
fn block_driver_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = block_driver_cleanup_view_v1(&BlockDriverCleanupManifest {
        id: 126,
        io_cleanup: 44,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 30,
        device_generation: 1,
        driver_binding: 33,
        driver_binding_generation: 1,
        block_device: 31,
        block_device_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 34,
            generation: 1,
        },
        cancelled_block_waits: vec![ContractObjectRefManifest {
            kind: "block-wait".to_owned(),
            id: 103,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 102,
            generation: 1,
        }],
        revoked_device_capabilities: vec![ContractObjectRefManifest {
            kind: "device-capability".to_owned(),
            id: 32,
            generation: 1,
        }],
        released_dma_buffers: vec![ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 106,
            generation: 1,
        }],
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 126,
        completed_at_event: Some(127),
        reason: "virtio-blk-device-fault".to_owned(),
        note: "block driver cleanup".to_owned(),
    });
    assert_eq!(view["kind"], "block-driver-cleanup");
    assert_eq!(view["owner"]["driver_store"]["generation"], 3);
    assert_eq!(view["owner"]["block_device"]["id"], 31);
    assert_eq!(view["references"]["io_cleanup"]["id"], 44);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-blk-backend-object");
    assert_eq!(view["references"]["cancelled_block_waits"][0]["id"], 103);
    assert_eq!(view["references"]["cancelled_wait_tokens"][0]["id"], 102);
    assert_eq!(view["references"]["revoked_device_capabilities"][0]["id"], 32);
    assert_eq!(view["references"]["released_dma_buffers"][0]["id"], 106);
    assert_eq!(view["cleanup"]["reason"], "virtio-blk-device-fault");
    assert_eq!(view["cleanup"]["cancelled_block_wait_count"], 1);
    assert_eq!(view["cleanup"]["released_dma_buffer_count"], 1);
    assert_eq!(view["cleanup"]["revoked_device_capability_count"], 1);
    assert_eq!(view["last_transition"]["completed_at_event"], 127);
}

#[test]
fn block_pending_io_policy_view_v1_exposes_retry_and_eio_policy() {
    let retry_policy = BlockPendingIoPolicyManifest {
        id: 127,
        block_wait: 103,
        block_wait_generation: 1,
        wait: 102,
        wait_generation: 1,
        block_request: 101,
        block_request_generation: 1,
        retry_request: Some(112),
        retry_request_generation: Some(1),
        block_device: 31,
        block_device_generation: 1,
        block_range: 100,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 2,
        byte_len: 4096,
        action: "retry".to_owned(),
        errno: 11,
        retry_attempt: 1,
        max_retries: 2,
        generation: 1,
        state: "retry-scheduled".to_owned(),
        recorded_at_event: 128,
        note: "pending io retry policy".to_owned(),
    };
    let view = block_pending_io_policy_view_v1(&retry_policy);
    assert_eq!(view["kind"], "block-pending-io-policy");
    assert_eq!(view["owner"]["block_wait"]["id"], 103);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["retry_request"]["id"], 112);
    assert_eq!(view["policy"]["action"], "retry");
    assert_eq!(view["policy"]["retry_attempt"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 128);
    assert!(view["last_error"].is_null());

    let eio = block_pending_io_policy_view_v1(&BlockPendingIoPolicyManifest {
        id: 129,
        retry_request: None,
        retry_request_generation: None,
        action: "eio".to_owned(),
        errno: 5,
        retry_attempt: 0,
        max_retries: 0,
        state: "eio-returned".to_owned(),
        recorded_at_event: 130,
        note: "pending io eio policy".to_owned(),
        ..retry_policy
    });
    assert_eq!(eio["last_error"]["errno"], 5);
}

#[test]
fn block_request_generation_audit_view_v1_exposes_exact_generation_refs() {
    let view = block_request_generation_audit_view_v1(&BlockRequestGenerationAuditManifest {
        id: 131,
        block_device: 2,
        block_device_generation: 3,
        block_range: 5,
        block_range_generation: 7,
        block_request: 11,
        block_request_generation: 13,
        backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 17,
            generation: 19,
        },
        dma_buffer: ContractObjectRefManifest {
            kind: "dma-buffer-object".to_owned(),
            id: 23,
            generation: 29,
        },
        rejected_completion_generation_probes: 1,
        rejected_wait_generation_probes: 2,
        rejected_dma_generation_probes: 3,
        rejected_queue_generation_probes: 4,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 31,
        note: "stale request generation audit".to_owned(),
    });
    assert_eq!(view["kind"], "block-request-generation-audit");
    assert_eq!(view["owner"]["block_request"]["generation"], 13);
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["backend"]["generation"], 19);
    assert_eq!(view["references"]["dma_buffer"]["kind"], "dma-buffer-object");
    assert_eq!(view["references"]["dma_buffer"]["generation"], 29);
    assert_eq!(view["audit"]["rejected_completion_generation_probes"], 1);
    assert_eq!(view["audit"]["rejected_wait_generation_probes"], 2);
    assert_eq!(view["audit"]["rejected_dma_generation_probes"], 3);
    assert_eq!(view["audit"]["rejected_queue_generation_probes"], 4);
    assert_eq!(view["last_transition"]["recorded_at_event"], 31);
}

#[test]
fn block_benchmark_view_v1_exposes_iops_latency_and_exact_refs() {
    let view = block_benchmark_view_v1(&BlockBenchmarkManifest {
        id: 132,
        scenario: "fake-block-read-write-iops-latency-v1".to_owned(),
        backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 26,
            generation: 1,
        },
        block_device: 2,
        block_device_generation: 1,
        block_range: 5,
        block_range_generation: 1,
        read_path: 39,
        read_path_generation: 1,
        write_path: 48,
        write_path_generation: 1,
        request_queue: 53,
        request_queue_generation: 1,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        sample_requests: 2,
        sample_bytes: 8192,
        read_completed_requests: 1,
        write_completed_requests: 1,
        queue_completed_requests: 2,
        measured_nanos: 40_000,
        budget_nanos: 80_000,
        iops: 50_000,
        throughput_bytes_per_sec: 204_800_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 35_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 487,
        note: "disk benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "block-benchmark");
    assert_eq!(view["references"]["backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["block_device"]["generation"], 1);
    assert_eq!(view["references"]["read_path"]["id"], 39);
    assert_eq!(view["references"]["write_path"]["id"], 48);
    assert_eq!(view["references"]["request_queue"]["id"], 53);
    assert_eq!(view["references"]["block_dma_buffer"]["id"], 61);
    assert_eq!(view["benchmark"]["sample_requests"], 2);
    assert_eq!(view["benchmark"]["iops"], 50_000);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 204_800_000);
    assert_eq!(view["benchmark"]["p99_latency_nanos"], 35_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 487);
}

#[test]
fn block_recovery_benchmark_view_v1_exposes_cleanup_latency_and_effects() {
    let view = block_recovery_benchmark_view_v1(&BlockRecoveryBenchmarkManifest {
        id: 135,
        scenario: "host-validation-disk-driver-recovery".to_owned(),
        cleanup: 107,
        cleanup_generation: 1,
        io_cleanup: 108,
        io_cleanup_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 34,
            generation: 1,
        },
        block_device: 31,
        block_device_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 30,
        device_generation: 1,
        driver_binding: 33,
        driver_binding_generation: 1,
        recovery_start_event: 125,
        recovery_complete_event: 126,
        cancelled_block_waits: 1,
        cancelled_wait_tokens: 1,
        released_dma_buffers: 1,
        revoked_device_capabilities: 1,
        recovery_nanos: 70_000,
        budget_nanos: 150_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 488,
        note: "disk recovery benchmark".to_owned(),
    });
    assert_eq!(view["kind"], "block-recovery-benchmark");
    assert_eq!(view["references"]["cleanup"]["kind"], "block-driver-cleanup");
    assert_eq!(view["references"]["io_cleanup"]["id"], 108);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-blk-backend-object");
    assert_eq!(view["references"]["block_device"]["id"], 31);
    assert_eq!(view["references"]["driver_store"]["generation"], 3);
    assert_eq!(view["benchmark"]["cancelled_block_waits"], 1);
    assert_eq!(view["benchmark"]["released_dma_buffers"], 1);
    assert_eq!(view["benchmark"]["recovery_nanos"], 70_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 488);
}
