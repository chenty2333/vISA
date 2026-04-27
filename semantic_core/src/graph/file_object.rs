use super::*;

fn byte_ranges_overlap(left_offset: u64, left_len: u64, right_offset: u64, right_len: u64) -> bool {
    let Some(left_end) = left_offset.checked_add(left_len) else {
        return true;
    };
    let Some(right_end) = right_offset.checked_add(right_len) else {
        return true;
    };
    left_offset < right_end && right_offset < left_end
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_file_object(
        &self,
        file_object: FileObjectId,
        buffer_cache_object: BufferCacheObjectId,
        buffer_cache_object_generation: Generation,
        namespace: &str,
        file_key: &str,
        path: &str,
        file_offset: u64,
        byte_len: u64,
        file_size: u64,
        content_digest: u64,
        state: FileObjectState,
    ) -> Result<(), &'static str> {
        if file_object == 0 {
            return Err("file object id=0 is invalid");
        }
        if self
            .file_objects
            .iter()
            .any(|record| record.id == file_object)
        {
            return Err("file object already exists");
        }
        if buffer_cache_object_generation == 0
            || byte_len == 0
            || content_digest == 0
            || namespace.is_empty()
            || file_key.is_empty()
            || path.is_empty()
        {
            return Err("file object identity values must be nonzero");
        }
        if state == FileObjectState::Invalidated {
            return Err("file object cannot be recorded as invalidated");
        }
        let Some(source) = self.buffer_cache_objects.iter().find(|record| {
            record.id == buffer_cache_object
                && record.generation == buffer_cache_object_generation
                && record.state != BufferCacheObjectState::Invalidated
        }) else {
            return Err("file object buffer cache generation is missing");
        };
        let Some(file_end) = file_offset.checked_add(byte_len) else {
            return Err("file object byte range overflow");
        };
        if file_end > file_size || byte_len > source.byte_len {
            return Err("file object byte range exceeds file or cache");
        }
        if self.file_objects.iter().any(|record| {
            record.state != FileObjectState::Invalidated
                && record.namespace == namespace
                && record.file_key == file_key
                && byte_ranges_overlap(record.file_offset, record.byte_len, file_offset, byte_len)
        }) {
            return Err("file object range already materialized");
        }
        if self.file_objects.iter().any(|record| {
            record.state != FileObjectState::Invalidated
                && record.buffer_cache_object == buffer_cache_object
                && record.buffer_cache_object_generation == buffer_cache_object_generation
        }) {
            return Err("file object buffer cache already materialized");
        }
        if self.check_invariants().is_err() {
            return Err("file object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_file_object_with_id(
        &mut self,
        file_object: FileObjectId,
        buffer_cache_object: BufferCacheObjectId,
        buffer_cache_object_generation: Generation,
        namespace: &str,
        file_key: &str,
        path: &str,
        file_offset: u64,
        byte_len: u64,
        file_size: u64,
        content_digest: u64,
        state: FileObjectState,
        note: &str,
    ) -> bool {
        if self
            .validate_file_object(
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
            )
            .is_err()
        {
            return false;
        }
        let Some(source) = self.buffer_cache_objects.iter().find(|record| {
            record.id == buffer_cache_object && record.generation == buffer_cache_object_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_file_object_id = self.next_file_object_id.max(file_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::FileObjectRecorded {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                block_device: source.block_device,
                block_device_generation: source.block_device_generation,
                block_range: source.block_range,
                block_range_generation: source.block_range_generation,
                page: source.page,
                page_dirty_generation: source.page_dirty_generation,
                namespace: namespace.to_string(),
                file_key: file_key.to_string(),
                path: path.to_string(),
                file_offset,
                byte_len,
                file_size,
                content_digest,
                cache_state: source.cache_state,
                state,
                generation,
            },
        );
        self.file_objects.push(FileObjectRecord {
            id: file_object,
            buffer_cache_object,
            buffer_cache_object_generation,
            block_device: source.block_device,
            block_device_generation: source.block_device_generation,
            block_range: source.block_range,
            block_range_generation: source.block_range_generation,
            page: source.page,
            page_dirty_generation: source.page_dirty_generation,
            namespace: namespace.to_string(),
            file_key: file_key.to_string(),
            path: path.to_string(),
            file_offset,
            byte_len,
            file_size,
            content_digest,
            cache_state: source.cache_state,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn file_objects(&self) -> &[FileObjectRecord] {
        &self.file_objects
    }

    pub fn file_object_count(&self) -> usize {
        self.file_objects.len()
    }

    pub fn check_file_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.file_objects {
            let Some(source) = self.buffer_cache_objects.iter().find(|cache| {
                cache.id == record.buffer_cache_object
                    && cache.generation == record.buffer_cache_object_generation
            }) else {
                return Err(SemanticInvariantError::FileObjectMissingBufferCacheObject {
                    file_object: record.id,
                    buffer_cache_object: record.buffer_cache_object,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.buffer_cache_object_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.page.kind != ContractObjectKind::PageObject
                || record.page.id == 0
                || record.page.generation == 0
                || record.page_dirty_generation == 0
                || record.namespace.is_empty()
                || record.file_key.is_empty()
                || record.path.is_empty()
                || record.byte_len == 0
                || record.content_digest == 0
                || record.state == FileObjectState::Invalidated
                || source.state == BufferCacheObjectState::Invalidated
                || record.block_device != source.block_device
                || record.block_device_generation != source.block_device_generation
                || record.block_range != source.block_range
                || record.block_range_generation != source.block_range_generation
                || record.page != source.page
                || record.page_dirty_generation != source.page_dirty_generation
                || record.cache_state != source.cache_state
                || record.byte_len > source.byte_len
                || record
                    .file_offset
                    .checked_add(record.byte_len)
                    .is_none_or(|end| end > record.file_size)
            {
                return Err(SemanticInvariantError::FileObjectInvalid {
                    file_object: record.id,
                });
            }
            if let Some(duplicate) = self.file_objects.iter().find(|other| {
                other.id != record.id
                    && other.state != FileObjectState::Invalidated
                    && other.namespace == record.namespace
                    && other.file_key == record.file_key
                    && byte_ranges_overlap(
                        other.file_offset,
                        other.byte_len,
                        record.file_offset,
                        record.byte_len,
                    )
            }) {
                return Err(SemanticInvariantError::FileObjectDuplicateFileRange {
                    file_object: duplicate.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FileObjectRecorded {
                            file_object,
                            buffer_cache_object,
                            buffer_cache_object_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            page,
                            page_dirty_generation,
                            namespace,
                            file_key,
                            path,
                            file_offset,
                            byte_len,
                            file_size,
                            content_digest,
                            cache_state,
                            state,
                            generation,
                        } if *file_object == record.id
                            && *buffer_cache_object == record.buffer_cache_object
                            && *buffer_cache_object_generation == record.buffer_cache_object_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *page == record.page
                            && *page_dirty_generation == record.page_dirty_generation
                            && namespace == &record.namespace
                            && file_key == &record.file_key
                            && path == &record.path
                            && *file_offset == record.file_offset
                            && *byte_len == record.byte_len
                            && *file_size == record.file_size
                            && *content_digest == record.content_digest
                            && *cache_state == record.cache_state
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FileObjectMissingEvent {
                    file_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_file_object_page_generation_for_test(
        &mut self,
        file_object: FileObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .file_objects
            .iter_mut()
            .find(|record| record.id == file_object)
        {
            record.page.generation = generation;
        }
    }
}
