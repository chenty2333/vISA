use super::*;

const BUFFER_CACHE_PAGE_SIZE_V1: u64 = 4096;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_buffer_cache_object(
        &self,
        buffer_cache_object: BufferCacheObjectId,
        block_page_object: BlockPageObjectId,
        block_page_object_generation: Generation,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        block_offset: u64,
        byte_len: u64,
        cache_state: BufferCacheObjectState,
        coherency_epoch: u64,
    ) -> Result<(), &'static str> {
        if buffer_cache_object == 0 {
            return Err("buffer cache object id=0 is invalid");
        }
        if self.buffer_cache_objects.iter().any(|record| record.id == buffer_cache_object) {
            return Err("buffer cache object already exists");
        }
        if block_page_object_generation == 0
            || page_dirty_generation == 0
            || byte_len == 0
            || coherency_epoch == 0
            || page.id == 0
            || page.generation == 0
        {
            return Err("buffer cache object identity values must be nonzero");
        }
        if page.kind != ContractObjectKind::PageObject {
            return Err("buffer cache object page kind is invalid");
        }
        if cache_state == BufferCacheObjectState::Invalidated {
            return Err("buffer cache object cannot be recorded as invalidated");
        }
        let Some(source) = self.block_page_objects.iter().find(|record| {
            record.id == block_page_object
                && record.generation == block_page_object_generation
                && record.state == BlockPageObjectState::Integrated
        }) else {
            return Err("buffer cache object page integration generation is missing");
        };
        if source.page != page || source.page_dirty_generation != page_dirty_generation {
            return Err("buffer cache object page ref does not match integration");
        }
        let Some(page_end) = source.page_offset.checked_add(byte_len) else {
            return Err("buffer cache object page byte range overflow");
        };
        if byte_len > source.byte_len || page_end > BUFFER_CACHE_PAGE_SIZE_V1 {
            return Err("buffer cache object byte range exceeds integrated page");
        }
        let Some(range_end) = block_offset.checked_add(byte_len) else {
            return Err("buffer cache object block byte range overflow");
        };
        let Some(block_range) = self.block_range_objects.iter().find(|range| {
            range.id == source.block_range
                && range.generation == source.block_range_generation
                && range.state == BlockRangeObjectState::Registered
        }) else {
            return Err("buffer cache object block range generation is missing");
        };
        if block_range.block_device != source.block_device
            || block_range.block_device_generation != source.block_device_generation
            || range_end > block_range.byte_len
        {
            return Err("buffer cache object block range does not match integration");
        }
        if self.buffer_cache_objects.iter().any(|record| {
            record.state != BufferCacheObjectState::Invalidated
                && record.block_device == source.block_device
                && record.block_device_generation == source.block_device_generation
                && record.block_range == source.block_range
                && record.block_range_generation == source.block_range_generation
                && record.block_offset == block_offset
                && record.byte_len == byte_len
        }) {
            return Err("buffer cache object block range already cached");
        }
        if self.buffer_cache_objects.iter().any(|record| {
            record.state != BufferCacheObjectState::Invalidated
                && record.page == source.page
                && record.page_offset == source.page_offset
                && record.byte_len == byte_len
        }) {
            return Err("buffer cache object page range already cached");
        }
        if self.check_invariants().is_err() {
            return Err("buffer cache object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_buffer_cache_object_with_id(
        &mut self,
        buffer_cache_object: BufferCacheObjectId,
        block_page_object: BlockPageObjectId,
        block_page_object_generation: Generation,
        page: ContractObjectRef,
        page_dirty_generation: Generation,
        block_offset: u64,
        byte_len: u64,
        cache_state: BufferCacheObjectState,
        coherency_epoch: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_buffer_cache_object(
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
            )
            .is_err()
        {
            return false;
        }
        let Some(source) = self.block_page_objects.iter().find(|record| {
            record.id == block_page_object && record.generation == block_page_object_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_buffer_cache_object_id =
            self.next_buffer_cache_object_id.max(buffer_cache_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BufferCacheObjectRecorded {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                block_dma_buffer: source.block_dma_buffer,
                block_dma_buffer_generation: source.block_dma_buffer_generation,
                block_device: source.block_device,
                block_device_generation: source.block_device_generation,
                block_range: source.block_range,
                block_range_generation: source.block_range_generation,
                aspace: source.aspace,
                vma_region: source.vma_region,
                page: source.page,
                page_dirty_generation,
                page_offset: source.page_offset,
                block_offset,
                byte_len,
                operation: source.operation,
                cache_state,
                coherency_epoch,
                generation,
            },
        );
        self.buffer_cache_objects.push(BufferCacheObjectRecord {
            id: buffer_cache_object,
            block_page_object,
            block_page_object_generation,
            block_dma_buffer: source.block_dma_buffer,
            block_dma_buffer_generation: source.block_dma_buffer_generation,
            block_device: source.block_device,
            block_device_generation: source.block_device_generation,
            block_range: source.block_range,
            block_range_generation: source.block_range_generation,
            aspace: source.aspace,
            vma_region: source.vma_region,
            page: source.page,
            page_dirty_generation,
            page_offset: source.page_offset,
            block_offset,
            byte_len,
            operation: source.operation,
            cache_state,
            coherency_epoch,
            generation,
            state: cache_state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn buffer_cache_objects(&self) -> &[BufferCacheObjectRecord] {
        &self.buffer_cache_objects
    }

    pub fn buffer_cache_object_count(&self) -> usize {
        self.buffer_cache_objects.len()
    }

    pub fn check_buffer_cache_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.buffer_cache_objects {
            let Some(source) = self.block_page_objects.iter().find(|page| {
                page.id == record.block_page_object
                    && page.generation == record.block_page_object_generation
            }) else {
                return Err(SemanticInvariantError::BufferCacheObjectMissingBlockPageObject {
                    buffer_cache_object: record.id,
                    block_page_object: record.block_page_object,
                });
            };
            let Some(block_range) = self.block_range_objects.iter().find(|range| {
                range.id == record.block_range && range.generation == record.block_range_generation
            }) else {
                return Err(SemanticInvariantError::BufferCacheObjectInvalid {
                    buffer_cache_object: record.id,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.block_page_object_generation == 0
                || record.block_dma_buffer_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.page.kind != ContractObjectKind::PageObject
                || record.page.id == 0
                || record.page.generation == 0
                || record.page_dirty_generation == 0
                || record.byte_len == 0
                || record.coherency_epoch == 0
                || record.state == BufferCacheObjectState::Invalidated
                || record.cache_state == BufferCacheObjectState::Invalidated
                || source.state != BlockPageObjectState::Integrated
                || record.block_dma_buffer != source.block_dma_buffer
                || record.block_dma_buffer_generation != source.block_dma_buffer_generation
                || record.block_device != source.block_device
                || record.block_device_generation != source.block_device_generation
                || record.block_range != source.block_range
                || record.block_range_generation != source.block_range_generation
                || record.aspace != source.aspace
                || record.vma_region != source.vma_region
                || record.page != source.page
                || record.page_dirty_generation != source.page_dirty_generation
                || record.page_offset != source.page_offset
                || record.operation != source.operation
                || record.byte_len > source.byte_len
                || record
                    .page_offset
                    .checked_add(record.byte_len)
                    .is_none_or(|end| end > BUFFER_CACHE_PAGE_SIZE_V1)
                || block_range.state != BlockRangeObjectState::Registered
                || block_range.block_device != record.block_device
                || block_range.block_device_generation != record.block_device_generation
                || record
                    .block_offset
                    .checked_add(record.byte_len)
                    .is_none_or(|end| end > block_range.byte_len)
            {
                return Err(SemanticInvariantError::BufferCacheObjectInvalid {
                    buffer_cache_object: record.id,
                });
            }
            if let Some(duplicate) = self.buffer_cache_objects.iter().find(|other| {
                other.id != record.id
                    && other.state != BufferCacheObjectState::Invalidated
                    && other.block_device == record.block_device
                    && other.block_device_generation == record.block_device_generation
                    && other.block_range == record.block_range
                    && other.block_range_generation == record.block_range_generation
                    && other.block_offset == record.block_offset
                    && other.byte_len == record.byte_len
            }) {
                return Err(SemanticInvariantError::BufferCacheObjectDuplicateBlockRange {
                    buffer_cache_object: duplicate.id,
                    block_range: record.block_range,
                });
            }
            if let Some(duplicate) = self.buffer_cache_objects.iter().find(|other| {
                other.id != record.id
                    && other.state != BufferCacheObjectState::Invalidated
                    && other.page == record.page
                    && other.page_offset == record.page_offset
                    && other.byte_len == record.byte_len
            }) {
                return Err(SemanticInvariantError::BufferCacheObjectDuplicatePageRange {
                    buffer_cache_object: duplicate.id,
                    page: record.page,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BufferCacheObjectRecorded {
                            buffer_cache_object,
                            block_page_object,
                            block_page_object_generation,
                            block_dma_buffer,
                            block_dma_buffer_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            aspace,
                            vma_region,
                            page,
                            page_dirty_generation,
                            page_offset,
                            block_offset,
                            byte_len,
                            operation,
                            cache_state,
                            coherency_epoch,
                            generation,
                        } if *buffer_cache_object == record.id
                            && *block_page_object == record.block_page_object
                            && *block_page_object_generation == record.block_page_object_generation
                            && *block_dma_buffer == record.block_dma_buffer
                            && *block_dma_buffer_generation == record.block_dma_buffer_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *aspace == record.aspace
                            && *vma_region == record.vma_region
                            && *page == record.page
                            && *page_dirty_generation == record.page_dirty_generation
                            && *page_offset == record.page_offset
                            && *block_offset == record.block_offset
                            && *byte_len == record.byte_len
                            && *operation == record.operation
                            && *cache_state == record.cache_state
                            && *coherency_epoch == record.coherency_epoch
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BufferCacheObjectMissingEvent {
                    buffer_cache_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_buffer_cache_object_page_generation_for_test(
        &mut self,
        buffer_cache_object: BufferCacheObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.buffer_cache_objects.iter_mut().find(|record| record.id == buffer_cache_object)
        {
            record.page.generation = generation;
        }
    }
}
