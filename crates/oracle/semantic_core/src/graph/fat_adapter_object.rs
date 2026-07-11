use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_fat_adapter_object(
        &self,
        fat_adapter_object: FatAdapterObjectId,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        implementation: &str,
        version: &str,
        profile: &str,
        volume_label: &str,
        image_bytes: u64,
        adapter_path: &str,
        semantic_path: &str,
        bytes_written: u64,
        bytes_read: u64,
        write_digest: u64,
        read_digest: u64,
        file_content_digest: u64,
        state: FatAdapterObjectState,
    ) -> Result<(), &'static str> {
        if fat_adapter_object == 0 {
            return Err("fat adapter object id=0 is invalid");
        }
        if self
            .domains
            .block
            .fat_adapter_objects
            .iter()
            .any(|record| record.id == fat_adapter_object)
        {
            return Err("fat adapter object already exists");
        }
        if directory_object_generation == 0
            || file_object_generation == 0
            || block_device_generation == 0
            || implementation.is_empty()
            || version.is_empty()
            || profile.is_empty()
            || volume_label.is_empty()
            || image_bytes == 0
            || adapter_path.is_empty()
            || semantic_path.is_empty()
            || bytes_written == 0
            || bytes_read == 0
            || write_digest == 0
            || read_digest == 0
            || file_content_digest == 0
        {
            return Err("fat adapter object identity values must be nonzero");
        }
        if state != FatAdapterObjectState::Verified {
            return Err("fat adapter object must be verified");
        }
        if bytes_written != bytes_read || write_digest != read_digest {
            return Err("fat adapter read/write roundtrip mismatch");
        }
        let Some(directory) = self.domains.block.directory_objects.iter().find(|record| {
            record.id == directory_object
                && record.generation == directory_object_generation
                && record.state != DirectoryObjectState::Invalidated
        }) else {
            return Err("fat adapter directory generation is missing");
        };
        let Some(file) = self.domains.block.file_objects.iter().find(|record| {
            record.id == file_object
                && record.generation == file_object_generation
                && record.state != FileObjectState::Invalidated
        }) else {
            return Err("fat adapter file generation is missing");
        };
        if directory.file_object != file_object
            || directory.file_object_generation != file_object_generation
            || directory.child_path != semantic_path
            || file.block_device != block_device
            || file.block_device_generation != block_device_generation
            || file.content_digest != file_content_digest
        {
            return Err("fat adapter semantic binding mismatch");
        }
        if self.domains.block.fat_adapter_objects.iter().any(|record| {
            record.state == FatAdapterObjectState::Verified
                && record.directory_object == directory_object
                && record.directory_object_generation == directory_object_generation
                && record.adapter_path == adapter_path
        }) {
            return Err("fat adapter binding already verified");
        }
        if self.check_invariants().is_err() {
            return Err("fat adapter object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_fat_adapter_object_with_id(
        &mut self,
        fat_adapter_object: FatAdapterObjectId,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        implementation: &str,
        version: &str,
        profile: &str,
        volume_label: &str,
        image_bytes: u64,
        adapter_path: &str,
        semantic_path: &str,
        bytes_written: u64,
        bytes_read: u64,
        write_digest: u64,
        read_digest: u64,
        file_content_digest: u64,
        state: FatAdapterObjectState,
        note: &str,
    ) -> bool {
        if self
            .validate_fat_adapter_object(
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
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.block.next_fat_adapter_object_id =
            self.domains.block.next_fat_adapter_object_id.max(fat_adapter_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::FatAdapterObjectRecorded {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation: implementation.to_string(),
                version: version.to_string(),
                profile: profile.to_string(),
                volume_label: volume_label.to_string(),
                image_bytes,
                adapter_path: adapter_path.to_string(),
                semantic_path: semantic_path.to_string(),
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                generation,
            },
        );
        self.domains.block.fat_adapter_objects.push(FatAdapterObjectRecord {
            id: fat_adapter_object,
            directory_object,
            directory_object_generation,
            file_object,
            file_object_generation,
            block_device,
            block_device_generation,
            implementation: implementation.to_string(),
            version: version.to_string(),
            profile: profile.to_string(),
            volume_label: volume_label.to_string(),
            image_bytes,
            adapter_path: adapter_path.to_string(),
            semantic_path: semantic_path.to_string(),
            bytes_written,
            bytes_read,
            write_digest,
            read_digest,
            file_content_digest,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn fat_adapter_objects(&self) -> &[FatAdapterObjectRecord] {
        &self.domains.block.fat_adapter_objects
    }

    pub fn fat_adapter_object_count(&self) -> usize {
        self.domains.block.fat_adapter_objects.len()
    }

    pub fn check_fat_adapter_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.fat_adapter_objects {
            let Some(directory) = self.domains.block.directory_objects.iter().find(|directory| {
                directory.id == record.directory_object
                    && directory.generation == record.directory_object_generation
            }) else {
                return Err(SemanticInvariantError::FatAdapterObjectMissingDirectoryObject {
                    fat_adapter_object: record.id,
                    directory_object: record.directory_object,
                });
            };
            let Some(file) = self.domains.block.file_objects.iter().find(|file| {
                file.id == record.file_object && file.generation == record.file_object_generation
            }) else {
                return Err(SemanticInvariantError::FatAdapterObjectMissingFileObject {
                    fat_adapter_object: record.id,
                    file_object: record.file_object,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.directory_object_generation == 0
                || record.file_object_generation == 0
                || record.block_device_generation == 0
                || record.implementation.is_empty()
                || record.version.is_empty()
                || record.profile.is_empty()
                || record.volume_label.is_empty()
                || record.image_bytes == 0
                || record.adapter_path.is_empty()
                || record.semantic_path.is_empty()
                || record.bytes_written == 0
                || record.bytes_read == 0
                || record.bytes_written != record.bytes_read
                || record.write_digest == 0
                || record.read_digest == 0
                || record.write_digest != record.read_digest
                || record.file_content_digest == 0
                || record.state != FatAdapterObjectState::Verified
                || directory.state == DirectoryObjectState::Invalidated
                || file.state == FileObjectState::Invalidated
                || directory.file_object != record.file_object
                || directory.file_object_generation != record.file_object_generation
                || directory.child_path != record.semantic_path
                || file.block_device != record.block_device
                || file.block_device_generation != record.block_device_generation
                || file.content_digest != record.file_content_digest
            {
                return Err(SemanticInvariantError::FatAdapterObjectInvalid {
                    fat_adapter_object: record.id,
                });
            }
            if let Some(duplicate) = self.domains.block.fat_adapter_objects.iter().find(|other| {
                other.id != record.id
                    && other.state == FatAdapterObjectState::Verified
                    && other.directory_object == record.directory_object
                    && other.directory_object_generation == record.directory_object_generation
                    && other.adapter_path == record.adapter_path
            }) {
                return Err(SemanticInvariantError::FatAdapterObjectDuplicateBinding {
                    fat_adapter_object: duplicate.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FatAdapterObjectRecorded {
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
                            generation,
                        } if *fat_adapter_object == record.id
                            && *directory_object == record.directory_object
                            && *directory_object_generation == record.directory_object_generation
                            && *file_object == record.file_object
                            && *file_object_generation == record.file_object_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && implementation == &record.implementation
                            && version == &record.version
                            && profile == &record.profile
                            && volume_label == &record.volume_label
                            && *image_bytes == record.image_bytes
                            && adapter_path == &record.adapter_path
                            && semantic_path == &record.semantic_path
                            && *bytes_written == record.bytes_written
                            && *bytes_read == record.bytes_read
                            && *write_digest == record.write_digest
                            && *read_digest == record.read_digest
                            && *file_content_digest == record.file_content_digest
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FatAdapterObjectMissingEvent {
                    fat_adapter_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_fat_adapter_file_generation_for_test(
        &mut self,
        fat_adapter_object: FatAdapterObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .block
            .fat_adapter_objects
            .iter_mut()
            .find(|record| record.id == fat_adapter_object)
        {
            record.file_object_generation = generation;
        }
    }
}
