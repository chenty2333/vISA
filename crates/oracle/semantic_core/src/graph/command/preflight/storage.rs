use super::*;

impl SemanticGraph {
    pub(super) fn preflight_storage_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RecordDeviceObject {
                device,
                name,
                class,
                resource,
                resource_generation,
                backend,
                ..
            } => self
                .validate_device_object(
                    *device,
                    name,
                    class,
                    *resource,
                    *resource_generation,
                    backend,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDeviceObject {
                packet_device,
                name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                ..
            } => self
                .validate_packet_device_object(
                    *packet_device,
                    name,
                    *device,
                    *device_generation,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *frame_format_version,
                    *max_payload_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                ..
            } => self
                .validate_packet_buffer_object(
                    *packet_buffer,
                    *packet_device,
                    *packet_device_generation,
                    *direction,
                    *frame_format_version,
                    *capacity,
                    *payload_len,
                    *sequence,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketQueueObject {
                packet_queue,
                name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                ..
            } => self
                .validate_packet_queue_object(
                    *packet_queue,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *role,
                    *queue_index,
                    *depth,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                ..
            } => self
                .validate_packet_descriptor_object(
                    *packet_descriptor,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *slot,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend,
                name,
                packet_device,
                packet_device_generation,
                provider,
                profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                ..
            } => self
                .validate_fake_net_backend_object(
                    *fake_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    provider,
                    profile,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeBlockBackendObject {
                fake_block_backend,
                name,
                block_device,
                block_device_generation,
                provider,
                profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                ..
            } => self
                .validate_fake_block_backend_object(
                    *fake_block_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    provider,
                    profile,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend,
                name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_blk_backend_object(
                    *virtio_blk_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *request_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockReadPath {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                data_digest,
                ..
            } => self
                .validate_block_read_path(
                    *read_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *data_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWritePath {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
                ..
            } => self
                .validate_block_write_path(
                    *write_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestQueue {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                entries,
                ..
            } => self
                .validate_block_request_queue(
                    *queue,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *depth,
                    entries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockDmaBuffer {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
                ..
            } => self
                .validate_block_dma_buffer(
                    *block_dma_buffer,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *dma_buffer,
                    *dma_buffer_generation,
                    *buffer_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockPageObject {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_completion,
                block_completion_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_backing,
                cow_state,
                page_state,
                page_offset,
                byte_len,
                ..
            } => self
                .validate_block_page_object(
                    *block_page_object,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *block_completion,
                    *block_completion_generation,
                    *aspace,
                    *vma_region,
                    *page,
                    *page_dirty_generation,
                    *page_backing,
                    *cow_state,
                    *page_state,
                    *page_offset,
                    *byte_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBufferCacheObject {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
                ..
            } => self
                .validate_buffer_cache_object(
                    *buffer_cache_object,
                    *block_page_object,
                    *block_page_object_generation,
                    *page,
                    *page_dirty_generation,
                    *block_offset,
                    *byte_len,
                    *cache_state,
                    *coherency_epoch,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileObject {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_file_object(
                    *file_object,
                    *buffer_cache_object,
                    *buffer_cache_object_generation,
                    namespace,
                    file_key,
                    path,
                    *file_offset,
                    *byte_len,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDirectoryObject {
                directory_object,
                file_object,
                file_object_generation,
                namespace,
                directory_key,
                directory_path,
                entry_name,
                child_file_key,
                child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_directory_object(
                    *directory_object,
                    *file_object,
                    *file_object_generation,
                    namespace,
                    directory_key,
                    directory_path,
                    entry_name,
                    child_file_key,
                    child_path,
                    *entry_kind,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFatAdapterObject {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                ..
            } => self
                .validate_fat_adapter_object(
                    *fat_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_written,
                    *bytes_read,
                    *write_digest,
                    *read_digest,
                    *file_content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordExt4AdapterObject {
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                ..
            } => self
                .validate_ext4_adapter_object(
                    *ext4_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_read,
                    *read_digest,
                    *file_content_digest,
                    *directory_entries,
                    *read_only_enforced,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileHandleCapability {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle,
                operation,
                file_offset,
                byte_len,
                content_digest,
                ..
            } => self
                .validate_file_handle_capability(
                    *file_handle_capability,
                    *owner_store,
                    *owner_store_generation,
                    *file_object,
                    *file_object_generation,
                    *directory_object,
                    *directory_object_generation,
                    *capability,
                    *capability_generation,
                    handle,
                    operation,
                    *file_offset,
                    *byte_len,
                    *content_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFsWait {
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_fs_wait(
                    *fs_wait,
                    *wait,
                    *wait_generation,
                    *file_handle_capability,
                    *file_handle_capability_generation,
                    operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveFsWait { fs_wait, fs_wait_generation, .. } => {
                if self.domains.block.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("fs wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CancelFsWait { fs_wait, fs_wait_generation, reason, .. } => {
                if !matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "fs wait cancellation reason is not a filesystem reason",
                    ));
                }
                if self.domains.block.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("fs wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CleanupBlockDriver {
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_block_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *block_device,
                    *block_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
