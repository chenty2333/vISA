use super::{super::super::*, *};

pub(crate) fn device_object_manifest(
    device: &semantic_core::DeviceObjectRecord,
) -> DeviceObjectManifest {
    DeviceObjectManifest {
        id: device.id,
        name: device.name.clone(),
        class: device.class.clone(),
        resource: device.resource,
        resource_generation: device.resource_generation,
        backend: device.backend.clone(),
        bus: device.bus.clone(),
        vendor: device.vendor.clone(),
        model: device.model.clone(),
        generation: device.generation,
        state: device.state.as_str().to_owned(),
        recorded_at_event: device.recorded_at_event,
        note: device.note.clone(),
    }
}

pub(crate) fn block_device_object_manifest(
    block_device: &semantic_core::BlockDeviceObjectRecord,
) -> BlockDeviceObjectManifest {
    BlockDeviceObjectManifest {
        id: block_device.id,
        name: block_device.name.clone(),
        device: block_device.device,
        device_generation: block_device.device_generation,
        sector_size: block_device.sector_size,
        sector_count: block_device.sector_count,
        read_only: block_device.read_only,
        max_transfer_sectors: block_device.max_transfer_sectors,
        generation: block_device.generation,
        state: block_device.state.as_str().to_owned(),
        recorded_at_event: block_device.recorded_at_event,
        note: block_device.note.clone(),
    }
}

pub(crate) fn block_range_object_manifest(
    block_range: &semantic_core::BlockRangeObjectRecord,
) -> BlockRangeObjectManifest {
    BlockRangeObjectManifest {
        id: block_range.id,
        block_device: block_range.block_device,
        block_device_generation: block_range.block_device_generation,
        start_sector: block_range.start_sector,
        sector_count: block_range.sector_count,
        byte_offset: block_range.byte_offset,
        byte_len: block_range.byte_len,
        generation: block_range.generation,
        state: block_range.state.as_str().to_owned(),
        recorded_at_event: block_range.recorded_at_event,
        note: block_range.note.clone(),
    }
}

pub(crate) fn block_request_object_manifest(
    request: &semantic_core::BlockRequestObjectRecord,
) -> BlockRequestObjectManifest {
    BlockRequestObjectManifest {
        id: request.id,
        block_device: request.block_device,
        block_device_generation: request.block_device_generation,
        block_range: request.block_range,
        block_range_generation: request.block_range_generation,
        operation: request.operation.as_str().to_owned(),
        sequence: request.sequence,
        byte_len: request.byte_len,
        generation: request.generation,
        state: request.state.as_str().to_owned(),
        recorded_at_event: request.recorded_at_event,
        note: request.note.clone(),
    }
}

pub(crate) fn block_completion_object_manifest(
    completion: &semantic_core::BlockCompletionObjectRecord,
) -> BlockCompletionObjectManifest {
    BlockCompletionObjectManifest {
        id: completion.id,
        block_request: completion.block_request,
        block_request_generation: completion.block_request_generation,
        block_device: completion.block_device,
        block_device_generation: completion.block_device_generation,
        block_range: completion.block_range,
        block_range_generation: completion.block_range_generation,
        sequence: completion.sequence,
        completed_bytes: completion.completed_bytes,
        status: completion.status.as_str().to_owned(),
        generation: completion.generation,
        state: completion.state.as_str().to_owned(),
        recorded_at_event: completion.recorded_at_event,
        note: completion.note.clone(),
    }
}

pub(crate) fn block_wait_manifest(wait: &semantic_core::BlockWaitRecord) -> BlockWaitManifest {
    BlockWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        block_request: wait.block_request,
        block_request_generation: wait.block_request_generation,
        block_device: wait.block_device,
        block_device_generation: wait.block_device_generation,
        block_range: wait.block_range,
        block_range_generation: wait.block_range_generation,
        operation: wait.operation.as_str().to_owned(),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        completion: wait.completion,
        completion_generation: wait.completion_generation,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn fake_block_backend_object_manifest(
    backend: &semantic_core::FakeBlockBackendObjectRecord,
) -> FakeBlockBackendObjectManifest {
    FakeBlockBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        deterministic_seed: backend.deterministic_seed,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn virtio_blk_backend_object_manifest(
    backend: &semantic_core::VirtioBlkBackendObjectRecord,
) -> VirtioBlkBackendObjectManifest {
    VirtioBlkBackendObjectManifest {
        id: backend.id,
        name: backend.name.clone(),
        block_device: backend.block_device,
        block_device_generation: backend.block_device_generation,
        driver_binding: backend.driver_binding,
        driver_binding_generation: backend.driver_binding_generation,
        device: backend.device,
        device_generation: backend.device_generation,
        provider: backend.provider.clone(),
        profile: backend.profile.clone(),
        model: backend.model.clone(),
        sector_size: backend.sector_size,
        sector_count: backend.sector_count,
        read_only: backend.read_only,
        max_transfer_sectors: backend.max_transfer_sectors,
        device_features: backend.device_features,
        driver_features: backend.driver_features,
        negotiated_features: backend.negotiated_features,
        request_queue_index: backend.request_queue_index,
        queue_size: backend.queue_size,
        irq_vector: backend.irq_vector,
        generation: backend.generation,
        state: backend.state.as_str().to_owned(),
        recorded_at_event: backend.recorded_at_event,
        note: backend.note.clone(),
    }
}

pub(crate) fn block_read_path_manifest(
    read_path: &semantic_core::BlockReadPathRecord,
) -> BlockReadPathManifest {
    BlockReadPathManifest {
        id: read_path.id,
        backend_kind: read_path.backend.kind.as_str().to_owned(),
        backend: read_path.backend.id,
        backend_generation: read_path.backend.generation,
        block_request: read_path.block_request,
        block_request_generation: read_path.block_request_generation,
        block_completion: read_path.block_completion,
        block_completion_generation: read_path.block_completion_generation,
        block_device: read_path.block_device,
        block_device_generation: read_path.block_device_generation,
        block_range: read_path.block_range,
        block_range_generation: read_path.block_range_generation,
        sequence: read_path.sequence,
        completed_bytes: read_path.completed_bytes,
        data_digest: read_path.data_digest,
        generation: read_path.generation,
        state: read_path.state.as_str().to_owned(),
        recorded_at_event: read_path.recorded_at_event,
        note: read_path.note.clone(),
    }
}

pub(crate) fn block_write_path_manifest(
    write_path: &semantic_core::BlockWritePathRecord,
) -> BlockWritePathManifest {
    BlockWritePathManifest {
        id: write_path.id,
        backend_kind: write_path.backend.kind.as_str().to_owned(),
        backend: write_path.backend.id,
        backend_generation: write_path.backend.generation,
        block_request: write_path.block_request,
        block_request_generation: write_path.block_request_generation,
        block_completion: write_path.block_completion,
        block_completion_generation: write_path.block_completion_generation,
        block_device: write_path.block_device,
        block_device_generation: write_path.block_device_generation,
        block_range: write_path.block_range,
        block_range_generation: write_path.block_range_generation,
        sequence: write_path.sequence,
        completed_bytes: write_path.completed_bytes,
        payload_digest: write_path.payload_digest,
        generation: write_path.generation,
        state: write_path.state.as_str().to_owned(),
        recorded_at_event: write_path.recorded_at_event,
        note: write_path.note.clone(),
    }
}

pub(crate) fn block_request_queue_manifest(
    queue: &semantic_core::BlockRequestQueueRecord,
) -> BlockRequestQueueManifest {
    BlockRequestQueueManifest {
        id: queue.id,
        backend_kind: queue.backend.kind.as_str().to_owned(),
        backend: queue.backend.id,
        backend_generation: queue.backend.generation,
        block_device: queue.block_device,
        block_device_generation: queue.block_device_generation,
        depth: queue.depth,
        entries: queue
            .entries
            .iter()
            .map(|entry| BlockRequestQueueEntryManifest {
                request: entry.request,
                request_generation: entry.request_generation,
                completion: entry.completion,
                completion_generation: entry.completion_generation,
                sequence: entry.sequence,
                operation: entry.operation.as_str().to_owned(),
                byte_len: entry.byte_len,
                state: entry.state.as_str().to_owned(),
            })
            .collect(),
        pending_count: queue.pending_count,
        completed_count: queue.completed_count,
        first_sequence: queue.first_sequence,
        last_sequence: queue.last_sequence,
        generation: queue.generation,
        state: queue.state.as_str().to_owned(),
        recorded_at_event: queue.recorded_at_event,
        note: queue.note.clone(),
    }
}

pub(crate) fn block_dma_buffer_manifest(
    buffer: &semantic_core::BlockDmaBufferRecord,
) -> BlockDmaBufferManifest {
    BlockDmaBufferManifest {
        id: buffer.id,
        backend_kind: buffer.backend.kind.as_str().to_owned(),
        backend: buffer.backend.id,
        backend_generation: buffer.backend.generation,
        block_request: buffer.block_request,
        block_request_generation: buffer.block_request_generation,
        dma_buffer: buffer.dma_buffer,
        dma_buffer_generation: buffer.dma_buffer_generation,
        block_device: buffer.block_device,
        block_device_generation: buffer.block_device_generation,
        block_range: buffer.block_range,
        block_range_generation: buffer.block_range_generation,
        descriptor: buffer.descriptor,
        descriptor_generation: buffer.descriptor_generation,
        queue: buffer.queue,
        queue_generation: buffer.queue_generation,
        operation: buffer.operation.as_str().to_owned(),
        access: buffer.access.as_str().to_owned(),
        byte_len: buffer.byte_len,
        buffer_len: buffer.buffer_len,
        buffer_digest: buffer.buffer_digest,
        generation: buffer.generation,
        state: buffer.state.as_str().to_owned(),
        recorded_at_event: buffer.recorded_at_event,
        note: buffer.note.clone(),
    }
}

pub(crate) fn block_page_object_manifest(
    page: &semantic_core::BlockPageObjectRecord,
) -> BlockPageObjectManifest {
    BlockPageObjectManifest {
        id: page.id,
        block_dma_buffer: page.block_dma_buffer,
        block_dma_buffer_generation: page.block_dma_buffer_generation,
        block_request: page.block_request,
        block_request_generation: page.block_request_generation,
        block_completion: page.block_completion,
        block_completion_generation: page.block_completion_generation,
        dma_buffer: page.dma_buffer,
        dma_buffer_generation: page.dma_buffer_generation,
        block_device: page.block_device,
        block_device_generation: page.block_device_generation,
        block_range: page.block_range,
        block_range_generation: page.block_range_generation,
        aspace: contract_object_ref_manifest(page.aspace),
        vma_region: contract_object_ref_manifest(page.vma_region),
        page: contract_object_ref_manifest(page.page),
        page_dirty_generation: page.page_dirty_generation,
        page_backing: page.page_backing.as_str().to_owned(),
        cow_state: page.cow_state.as_str().to_owned(),
        page_state: page.page_state.as_str().to_owned(),
        page_offset: page.page_offset,
        byte_len: page.byte_len,
        operation: page.operation.as_str().to_owned(),
        generation: page.generation,
        state: page.state.as_str().to_owned(),
        recorded_at_event: page.recorded_at_event,
        note: page.note.clone(),
    }
}

pub(crate) fn buffer_cache_object_manifest(
    cache: &semantic_core::BufferCacheObjectRecord,
) -> BufferCacheObjectManifest {
    BufferCacheObjectManifest {
        id: cache.id,
        block_page_object: cache.block_page_object,
        block_page_object_generation: cache.block_page_object_generation,
        block_dma_buffer: cache.block_dma_buffer,
        block_dma_buffer_generation: cache.block_dma_buffer_generation,
        block_device: cache.block_device,
        block_device_generation: cache.block_device_generation,
        block_range: cache.block_range,
        block_range_generation: cache.block_range_generation,
        aspace: contract_object_ref_manifest(cache.aspace),
        vma_region: contract_object_ref_manifest(cache.vma_region),
        page: contract_object_ref_manifest(cache.page),
        page_dirty_generation: cache.page_dirty_generation,
        page_offset: cache.page_offset,
        block_offset: cache.block_offset,
        byte_len: cache.byte_len,
        operation: cache.operation.as_str().to_owned(),
        cache_state: cache.cache_state.as_str().to_owned(),
        coherency_epoch: cache.coherency_epoch,
        generation: cache.generation,
        state: cache.state.as_str().to_owned(),
        recorded_at_event: cache.recorded_at_event,
        note: cache.note.clone(),
    }
}

pub(crate) fn file_object_manifest(file: &semantic_core::FileObjectRecord) -> FileObjectManifest {
    FileObjectManifest {
        id: file.id,
        buffer_cache_object: file.buffer_cache_object,
        buffer_cache_object_generation: file.buffer_cache_object_generation,
        block_device: file.block_device,
        block_device_generation: file.block_device_generation,
        block_range: file.block_range,
        block_range_generation: file.block_range_generation,
        page: contract_object_ref_manifest(file.page),
        page_dirty_generation: file.page_dirty_generation,
        namespace: file.namespace.clone(),
        file_key: file.file_key.clone(),
        path: file.path.clone(),
        file_offset: file.file_offset,
        byte_len: file.byte_len,
        file_size: file.file_size,
        content_digest: file.content_digest,
        cache_state: file.cache_state.as_str().to_owned(),
        generation: file.generation,
        state: file.state.as_str().to_owned(),
        recorded_at_event: file.recorded_at_event,
        note: file.note.clone(),
    }
}

pub(crate) fn directory_object_manifest(
    directory: &semantic_core::DirectoryObjectRecord,
) -> DirectoryObjectManifest {
    DirectoryObjectManifest {
        id: directory.id,
        file_object: directory.file_object,
        file_object_generation: directory.file_object_generation,
        namespace: directory.namespace.clone(),
        directory_key: directory.directory_key.clone(),
        directory_path: directory.directory_path.clone(),
        entry_name: directory.entry_name.clone(),
        child_file_key: directory.child_file_key.clone(),
        child_path: directory.child_path.clone(),
        entry_kind: directory.entry_kind.as_str().to_owned(),
        file_size: directory.file_size,
        content_digest: directory.content_digest,
        generation: directory.generation,
        state: directory.state.as_str().to_owned(),
        recorded_at_event: directory.recorded_at_event,
        note: directory.note.clone(),
    }
}

pub(crate) fn fat_adapter_object_manifest(
    adapter: &semantic_core::FatAdapterObjectRecord,
) -> FatAdapterObjectManifest {
    FatAdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_written: adapter.bytes_written,
        bytes_read: adapter.bytes_read,
        write_digest: adapter.write_digest,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn ext4_adapter_object_manifest(
    adapter: &semantic_core::Ext4AdapterObjectRecord,
) -> Ext4AdapterObjectManifest {
    Ext4AdapterObjectManifest {
        id: adapter.id,
        directory_object: adapter.directory_object,
        directory_object_generation: adapter.directory_object_generation,
        file_object: adapter.file_object,
        file_object_generation: adapter.file_object_generation,
        block_device: adapter.block_device,
        block_device_generation: adapter.block_device_generation,
        implementation: adapter.implementation.clone(),
        version: adapter.version.clone(),
        profile: adapter.profile.clone(),
        volume_label: adapter.volume_label.clone(),
        image_bytes: adapter.image_bytes,
        adapter_path: adapter.adapter_path.clone(),
        semantic_path: adapter.semantic_path.clone(),
        bytes_read: adapter.bytes_read,
        read_digest: adapter.read_digest,
        file_content_digest: adapter.file_content_digest,
        directory_entries: adapter.directory_entries,
        read_only_enforced: adapter.read_only_enforced,
        generation: adapter.generation,
        state: adapter.state.as_str().to_owned(),
        recorded_at_event: adapter.recorded_at_event,
        note: adapter.note.clone(),
    }
}

pub(crate) fn file_handle_capability_manifest(
    capability: &semantic_core::FileHandleCapabilityRecord,
) -> FileHandleCapabilityManifest {
    FileHandleCapabilityManifest {
        id: capability.id,
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        file_object: capability.file_object,
        file_object_generation: capability.file_object_generation,
        directory_object: capability.directory_object,
        directory_object_generation: capability.directory_object_generation,
        capability: capability.capability,
        capability_generation: capability.capability_generation,
        handle_slot: capability.handle_slot,
        handle_generation: capability.handle_generation,
        handle_tag: capability.handle_tag,
        operation: capability.operation.clone(),
        file_offset: capability.file_offset,
        byte_len: capability.byte_len,
        content_digest: capability.content_digest,
        generation: capability.generation,
        state: capability.state.as_str().to_owned(),
        recorded_at_event: capability.recorded_at_event,
        note: capability.note.clone(),
    }
}

pub(crate) fn fs_wait_manifest(wait: &semantic_core::FsWaitRecord) -> FsWaitManifest {
    FsWaitManifest {
        id: wait.id,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_store: wait.owner_store,
        owner_store_generation: wait.owner_store_generation,
        file_object: wait.file_object,
        file_object_generation: wait.file_object_generation,
        directory_object: wait.directory_object,
        directory_object_generation: wait.directory_object_generation,
        file_handle_capability: wait.file_handle_capability,
        file_handle_capability_generation: wait.file_handle_capability_generation,
        operation: wait.operation.clone(),
        blocker: contract_object_ref_manifest(wait.blocker),
        sequence: wait.sequence,
        byte_len: wait.byte_len,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        created_at_event: wait.created_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn block_driver_cleanup_manifest(
    cleanup: &semantic_core::BlockDriverCleanupRecord,
) -> BlockDriverCleanupManifest {
    BlockDriverCleanupManifest {
        id: cleanup.id,
        io_cleanup: cleanup.io_cleanup,
        io_cleanup_generation: cleanup.io_cleanup_generation,
        driver_store: cleanup.driver_store,
        driver_store_generation: cleanup.driver_store_generation,
        device: cleanup.device,
        device_generation: cleanup.device_generation,
        driver_binding: cleanup.driver_binding,
        driver_binding_generation: cleanup.driver_binding_generation,
        block_device: cleanup.block_device,
        block_device_generation: cleanup.block_device_generation,
        backend: contract_object_ref_manifest(cleanup.backend),
        cancelled_block_waits: cleanup
            .cancelled_block_waits
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        cancelled_wait_tokens: cleanup
            .cancelled_wait_tokens
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_device_capabilities: cleanup
            .revoked_device_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_dma_buffers: cleanup
            .released_dma_buffers
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        reason: cleanup.reason.clone(),
        note: cleanup.note.clone(),
    }
}
