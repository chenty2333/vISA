use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_ext4_adapter_object(
        &self,
        ext4_adapter_object: Ext4AdapterObjectId,
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
        bytes_read: u64,
        read_digest: u64,
        file_content_digest: u64,
        directory_entries: u64,
        read_only_enforced: bool,
        state: Ext4AdapterObjectState,
    ) -> Result<(), &'static str> {
        if ext4_adapter_object == 0 {
            return Err("ext4 adapter object id=0 is invalid");
        }
        if self
            .domains
            .block
            .ext4_adapter_objects
            .iter()
            .any(|record| record.id == ext4_adapter_object)
        {
            return Err("ext4 adapter object already exists");
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
            || bytes_read == 0
            || read_digest == 0
            || file_content_digest == 0
            || directory_entries == 0
        {
            return Err("ext4 adapter object identity values must be nonzero");
        }
        if state != Ext4AdapterObjectState::Verified || !read_only_enforced {
            return Err("ext4 adapter object must be verified read-only evidence");
        }
        let Some(directory) = self.domains.block.directory_objects.iter().find(|record| {
            record.id == directory_object
                && record.generation == directory_object_generation
                && record.state != DirectoryObjectState::Invalidated
        }) else {
            return Err("ext4 adapter directory generation is missing");
        };
        let Some(file) = self.domains.block.file_objects.iter().find(|record| {
            record.id == file_object
                && record.generation == file_object_generation
                && record.state != FileObjectState::Invalidated
        }) else {
            return Err("ext4 adapter file generation is missing");
        };
        if directory.file_object != file_object
            || directory.file_object_generation != file_object_generation
            || directory.child_path != semantic_path
            || file.block_device != block_device
            || file.block_device_generation != block_device_generation
            || file.content_digest != file_content_digest
        {
            return Err("ext4 adapter semantic binding mismatch");
        }
        if self.domains.block.ext4_adapter_objects.iter().any(|record| {
            record.state == Ext4AdapterObjectState::Verified
                && record.directory_object == directory_object
                && record.directory_object_generation == directory_object_generation
                && record.adapter_path == adapter_path
        }) {
            return Err("ext4 adapter binding already verified");
        }
        if self.check_invariants().is_err() {
            return Err("ext4 adapter object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_ext4_adapter_object_with_id(
        &mut self,
        ext4_adapter_object: Ext4AdapterObjectId,
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
        bytes_read: u64,
        read_digest: u64,
        file_content_digest: u64,
        directory_entries: u64,
        read_only_enforced: bool,
        state: Ext4AdapterObjectState,
        note: &str,
    ) -> bool {
        if self
            .validate_ext4_adapter_object(
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
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.block.next_ext4_adapter_object_id = self
            .domains
            .block
            .next_ext4_adapter_object_id
            .max(ext4_adapter_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::Ext4AdapterObjectRecorded {
                ext4_adapter_object,
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
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                generation,
            },
        );
        self.domains.block.ext4_adapter_objects.push(Ext4AdapterObjectRecord {
            id: ext4_adapter_object,
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
            bytes_read,
            read_digest,
            file_content_digest,
            directory_entries,
            read_only_enforced,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn ext4_adapter_objects(&self) -> &[Ext4AdapterObjectRecord] {
        &self.domains.block.ext4_adapter_objects
    }

    pub fn ext4_adapter_object_count(&self) -> usize {
        self.domains.block.ext4_adapter_objects.len()
    }

    pub fn check_ext4_adapter_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.ext4_adapter_objects {
            let Some(directory) = self.domains.block.directory_objects.iter().find(|directory| {
                directory.id == record.directory_object
                    && directory.generation == record.directory_object_generation
            }) else {
                return Err(SemanticInvariantError::Ext4AdapterObjectMissingDirectoryObject {
                    ext4_adapter_object: record.id,
                    directory_object: record.directory_object,
                });
            };
            let Some(file) = self.domains.block.file_objects.iter().find(|file| {
                file.id == record.file_object && file.generation == record.file_object_generation
            }) else {
                return Err(SemanticInvariantError::Ext4AdapterObjectMissingFileObject {
                    ext4_adapter_object: record.id,
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
                || record.bytes_read == 0
                || record.read_digest == 0
                || record.file_content_digest == 0
                || record.directory_entries == 0
                || !record.read_only_enforced
                || record.state != Ext4AdapterObjectState::Verified
                || directory.state == DirectoryObjectState::Invalidated
                || file.state == FileObjectState::Invalidated
                || directory.file_object != record.file_object
                || directory.file_object_generation != record.file_object_generation
                || directory.child_path != record.semantic_path
                || file.block_device != record.block_device
                || file.block_device_generation != record.block_device_generation
                || file.content_digest != record.file_content_digest
            {
                return Err(SemanticInvariantError::Ext4AdapterObjectInvalid {
                    ext4_adapter_object: record.id,
                });
            }
            if let Some(duplicate) = self.domains.block.ext4_adapter_objects.iter().find(|other| {
                other.id != record.id
                    && other.state == Ext4AdapterObjectState::Verified
                    && other.directory_object == record.directory_object
                    && other.directory_object_generation == record.directory_object_generation
                    && other.adapter_path == record.adapter_path
            }) {
                return Err(SemanticInvariantError::Ext4AdapterObjectDuplicateBinding {
                    ext4_adapter_object: duplicate.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::Ext4AdapterObjectRecorded {
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
                            generation,
                        } if *ext4_adapter_object == record.id
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
                            && *bytes_read == record.bytes_read
                            && *read_digest == record.read_digest
                            && *file_content_digest == record.file_content_digest
                            && *directory_entries == record.directory_entries
                            && *read_only_enforced == record.read_only_enforced
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::Ext4AdapterObjectMissingEvent {
                    ext4_adapter_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_ext4_adapter_file_generation_for_test(
        &mut self,
        ext4_adapter_object: Ext4AdapterObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .block
            .ext4_adapter_objects
            .iter_mut()
            .find(|record| record.id == ext4_adapter_object)
        {
            record.file_object_generation = generation;
        }
    }
}
