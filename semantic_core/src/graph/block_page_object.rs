use super::*;

const BLOCK_PAGE_OBJECT_PAGE_SIZE_V1: u64 = 4096;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_page_object(
        &self,
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        aspace: ContractObjectRef,
        vma_region: ContractObjectRef,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        page_backing: PageBacking,
        cow_state: CowState,
        page_state: PageObjectState,
        page_offset: u64,
        byte_len: u64,
    ) -> Result<(), &'static str> {
        if block_page_object == 0 {
            return Err("block page object id=0 is invalid");
        }
        if self.block_page_objects.iter().any(|record| record.id == block_page_object) {
            return Err("block page object already exists");
        }
        if block_dma_buffer_generation == 0
            || block_completion_generation == 0
            || page_dirty_generation == 0
            || byte_len == 0
            || aspace.id == 0
            || aspace.generation == 0
            || vma_region.id == 0
            || vma_region.generation == 0
            || page.id == 0
            || page.generation == 0
        {
            return Err("block page object identity values must be nonzero");
        }
        if aspace.kind != ContractObjectKind::GuestAddressSpace {
            return Err("block page object aspace kind is invalid");
        }
        if vma_region.kind != ContractObjectKind::VmaRegion {
            return Err("block page object VMA kind is invalid");
        }
        if page.kind != ContractObjectKind::PageObject {
            return Err("block page object page kind is invalid");
        }
        if page_state != PageObjectState::Live {
            return Err("block page object page must be live");
        }
        if matches!(page_backing, PageBacking::DeviceMemory | PageBacking::External) {
            return Err("block page object backing cannot be device or external memory");
        }
        if matches!(cow_state, CowState::Broken) {
            return Err("block page object COW break must be revalidated before IO");
        }
        let Some(page_end) = page_offset.checked_add(byte_len) else {
            return Err("block page object byte range overflow");
        };
        if page_end > BLOCK_PAGE_OBJECT_PAGE_SIZE_V1 {
            return Err("block page object byte range exceeds page");
        }
        let Some(buffer_record) = self.block_dma_buffers.iter().find(|record| {
            record.id == block_dma_buffer
                && record.generation == block_dma_buffer_generation
                && record.state == BlockDmaBufferState::Bound
        }) else {
            return Err("block page object dma buffer generation is missing or inactive");
        };
        let Some(completion_record) = self.block_completion_objects.iter().find(|completion| {
            completion.id == block_completion
                && completion.generation == block_completion_generation
                && completion.state == BlockCompletionObjectState::Recorded
        }) else {
            return Err("block page object completion generation is missing");
        };
        if completion_record.status != BlockCompletionStatus::Success {
            return Err("block page object requires successful completion");
        }
        if completion_record.block_request != buffer_record.block_request
            || completion_record.block_request_generation != buffer_record.block_request_generation
            || completion_record.block_device != buffer_record.block_device
            || completion_record.block_device_generation != buffer_record.block_device_generation
            || completion_record.block_range != buffer_record.block_range
            || completion_record.block_range_generation != buffer_record.block_range_generation
            || completion_record.completed_bytes != buffer_record.byte_len
        {
            return Err("block page object completion does not match dma buffer request");
        }
        if byte_len != buffer_record.byte_len {
            return Err("block page object byte length must match dma buffer");
        }
        if self.block_page_objects.iter().any(|record| {
            record.state == BlockPageObjectState::Integrated
                && record.block_dma_buffer == buffer_record.id
                && record.block_dma_buffer_generation == buffer_record.generation
        }) {
            return Err("block page object dma buffer already integrated");
        }
        if self.block_page_objects.iter().any(|record| {
            record.state == BlockPageObjectState::Integrated
                && record.page == page
                && record.page_offset == page_offset
                && record.byte_len == byte_len
        }) {
            return Err("block page object page range already integrated");
        }
        if self.check_invariants().is_err() {
            return Err("block page object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_page_object_with_id(
        &mut self,
        block_page_object: BlockPageObjectId,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        aspace: ContractObjectRef,
        vma_region: ContractObjectRef,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        page_backing: PageBacking,
        cow_state: CowState,
        page_state: PageObjectState,
        page_offset: u64,
        byte_len: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_block_page_object(
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
            )
            .is_err()
        {
            return false;
        }
        let Some(buffer_record) = self.block_dma_buffers.iter().find(|buffer| {
            buffer.id == block_dma_buffer && buffer.generation == block_dma_buffer_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_block_page_object_id =
            self.next_block_page_object_id.max(block_page_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockPageObjectIntegrated {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_request: buffer_record.block_request,
                block_request_generation: buffer_record.block_request_generation,
                block_completion,
                block_completion_generation,
                dma_buffer: buffer_record.dma_buffer,
                dma_buffer_generation: buffer_record.dma_buffer_generation,
                block_device: buffer_record.block_device,
                block_device_generation: buffer_record.block_device_generation,
                block_range: buffer_record.block_range,
                block_range_generation: buffer_record.block_range_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_offset,
                byte_len,
                operation: buffer_record.operation,
                generation,
            },
        );
        self.block_page_objects.push(BlockPageObjectRecord {
            id: block_page_object,
            block_dma_buffer,
            block_dma_buffer_generation,
            block_request: buffer_record.block_request,
            block_request_generation: buffer_record.block_request_generation,
            block_completion,
            block_completion_generation,
            dma_buffer: buffer_record.dma_buffer,
            dma_buffer_generation: buffer_record.dma_buffer_generation,
            block_device: buffer_record.block_device,
            block_device_generation: buffer_record.block_device_generation,
            block_range: buffer_record.block_range,
            block_range_generation: buffer_record.block_range_generation,
            aspace,
            vma_region,
            page,
            page_dirty_generation,
            page_backing,
            cow_state,
            page_state,
            page_offset,
            byte_len,
            operation: buffer_record.operation,
            generation,
            state: BlockPageObjectState::Integrated,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_page_objects(&self) -> &[BlockPageObjectRecord] {
        &self.block_page_objects
    }

    pub fn block_page_object_count(&self) -> usize {
        self.block_page_objects.len()
    }

    pub fn check_block_page_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_page_objects {
            let Some(buffer_record) = self.block_dma_buffers.iter().find(|buffer| {
                buffer.id == record.block_dma_buffer
                    && buffer.generation == record.block_dma_buffer_generation
            }) else {
                return Err(SemanticInvariantError::BlockPageObjectMissingDmaBuffer {
                    block_page_object: record.id,
                    block_dma_buffer: record.block_dma_buffer,
                });
            };
            let Some(completion_record) = self.block_completion_objects.iter().find(|completion| {
                completion.id == record.block_completion
                    && completion.generation == record.block_completion_generation
            }) else {
                return Err(SemanticInvariantError::BlockPageObjectMissingCompletion {
                    block_page_object: record.id,
                    block_completion: record.block_completion,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.block_dma_buffer_generation == 0
                || record.block_request_generation == 0
                || record.block_completion_generation == 0
                || record.dma_buffer_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.aspace.kind != ContractObjectKind::GuestAddressSpace
                || record.aspace.id == 0
                || record.aspace.generation == 0
                || record.vma_region.kind != ContractObjectKind::VmaRegion
                || record.vma_region.id == 0
                || record.vma_region.generation == 0
                || record.page.kind != ContractObjectKind::PageObject
                || record.page.id == 0
                || record.page.generation == 0
                || record.page_dirty_generation == 0
                || record.page_state != PageObjectState::Live
                || matches!(record.page_backing, PageBacking::DeviceMemory | PageBacking::External)
                || matches!(record.cow_state, CowState::Broken)
                || record.byte_len == 0
                || record
                    .page_offset
                    .checked_add(record.byte_len)
                    .is_none_or(|end| end > BLOCK_PAGE_OBJECT_PAGE_SIZE_V1)
                || record.state != BlockPageObjectState::Integrated
                || buffer_record.state != BlockDmaBufferState::Bound
                || completion_record.status != BlockCompletionStatus::Success
                || completion_record.state != BlockCompletionObjectState::Recorded
                || record.block_request != buffer_record.block_request
                || record.block_request_generation != buffer_record.block_request_generation
                || record.dma_buffer != buffer_record.dma_buffer
                || record.dma_buffer_generation != buffer_record.dma_buffer_generation
                || record.block_device != buffer_record.block_device
                || record.block_device_generation != buffer_record.block_device_generation
                || record.block_range != buffer_record.block_range
                || record.block_range_generation != buffer_record.block_range_generation
                || record.operation != buffer_record.operation
                || record.byte_len != buffer_record.byte_len
                || completion_record.block_request != record.block_request
                || completion_record.block_request_generation != record.block_request_generation
                || completion_record.block_device != record.block_device
                || completion_record.block_device_generation != record.block_device_generation
                || completion_record.block_range != record.block_range
                || completion_record.block_range_generation != record.block_range_generation
                || completion_record.completed_bytes != record.byte_len
            {
                return Err(SemanticInvariantError::BlockPageObjectInvalid {
                    block_page_object: record.id,
                });
            }
            if let Some(duplicate) = self.block_page_objects.iter().find(|other| {
                other.id != record.id
                    && other.state == BlockPageObjectState::Integrated
                    && other.block_dma_buffer == record.block_dma_buffer
                    && other.block_dma_buffer_generation == record.block_dma_buffer_generation
            }) {
                return Err(SemanticInvariantError::BlockPageObjectDuplicateDmaBuffer {
                    block_page_object: duplicate.id,
                    block_dma_buffer: record.block_dma_buffer,
                });
            }
            if let Some(duplicate) = self.block_page_objects.iter().find(|other| {
                other.id != record.id
                    && other.state == BlockPageObjectState::Integrated
                    && other.page == record.page
                    && other.page_offset == record.page_offset
                    && other.byte_len == record.byte_len
            }) {
                return Err(SemanticInvariantError::BlockPageObjectDuplicatePageRange {
                    block_page_object: duplicate.id,
                    page: record.page,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockPageObjectIntegrated {
                            block_page_object,
                            block_dma_buffer,
                            block_dma_buffer_generation,
                            block_request,
                            block_request_generation,
                            block_completion,
                            block_completion_generation,
                            dma_buffer,
                            dma_buffer_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            aspace,
                            vma_region,
                            page,
                            page_dirty_generation,
                            page_offset,
                            byte_len,
                            operation,
                            generation,
                        } if *block_page_object == record.id
                            && *block_dma_buffer == record.block_dma_buffer
                            && *block_dma_buffer_generation == record.block_dma_buffer_generation
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
                            && *block_completion == record.block_completion
                            && *block_completion_generation == record.block_completion_generation
                            && *dma_buffer == record.dma_buffer
                            && *dma_buffer_generation == record.dma_buffer_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *aspace == record.aspace
                            && *vma_region == record.vma_region
                            && *page == record.page
                            && *page_dirty_generation == record.page_dirty_generation
                            && *page_offset == record.page_offset
                            && *byte_len == record.byte_len
                            && *operation == record.operation
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockPageObjectMissingEvent {
                    block_page_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_page_object_page_generation_for_test(
        &mut self,
        block_page_object: BlockPageObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.block_page_objects.iter_mut().find(|record| record.id == block_page_object)
        {
            record.page.generation = generation;
        }
    }
}
