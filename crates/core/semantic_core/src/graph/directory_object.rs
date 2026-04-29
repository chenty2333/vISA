use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_directory_object(
        &self,
        directory_object: DirectoryObjectId,
        file_object: FileObjectId,
        file_object_generation: Generation,
        namespace: &str,
        directory_key: &str,
        directory_path: &str,
        entry_name: &str,
        child_file_key: &str,
        child_path: &str,
        entry_kind: DirectoryEntryKind,
        file_size: u64,
        content_digest: u64,
        state: DirectoryObjectState,
    ) -> Result<(), &'static str> {
        if directory_object == 0 {
            return Err("directory object id=0 is invalid");
        }
        if self.directory_objects.iter().any(|record| record.id == directory_object) {
            return Err("directory object already exists");
        }
        if file_object_generation == 0
            || namespace.is_empty()
            || directory_key.is_empty()
            || directory_path.is_empty()
            || entry_name.is_empty()
            || child_file_key.is_empty()
            || child_path.is_empty()
            || file_size == 0
            || content_digest == 0
        {
            return Err("directory object identity values must be nonzero");
        }
        if state == DirectoryObjectState::Invalidated {
            return Err("directory object cannot be recorded as invalidated");
        }
        let Some(source) = self.file_objects.iter().find(|record| {
            record.id == file_object
                && record.generation == file_object_generation
                && record.state != FileObjectState::Invalidated
        }) else {
            return Err("directory object file generation is missing");
        };
        if entry_kind != DirectoryEntryKind::File
            || namespace != source.namespace
            || child_file_key != source.file_key
            || child_path != source.path
            || file_size != source.file_size
            || content_digest != source.content_digest
        {
            return Err("directory object file identity mismatch");
        }
        if self.directory_objects.iter().any(|record| {
            record.state != DirectoryObjectState::Invalidated
                && record.namespace == namespace
                && record.directory_key == directory_key
                && record.entry_name == entry_name
        }) {
            return Err("directory object entry already materialized");
        }
        if self.check_invariants().is_err() {
            return Err("directory object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_directory_object_with_id(
        &mut self,
        directory_object: DirectoryObjectId,
        file_object: FileObjectId,
        file_object_generation: Generation,
        namespace: &str,
        directory_key: &str,
        directory_path: &str,
        entry_name: &str,
        child_file_key: &str,
        child_path: &str,
        entry_kind: DirectoryEntryKind,
        file_size: u64,
        content_digest: u64,
        state: DirectoryObjectState,
        note: &str,
    ) -> bool {
        if self
            .validate_directory_object(
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
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_directory_object_id =
            self.next_directory_object_id.max(directory_object.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::DirectoryObjectRecorded {
                directory_object,
                file_object,
                file_object_generation,
                namespace: namespace.to_string(),
                directory_key: directory_key.to_string(),
                directory_path: directory_path.to_string(),
                entry_name: entry_name.to_string(),
                child_file_key: child_file_key.to_string(),
                child_path: child_path.to_string(),
                entry_kind,
                file_size,
                content_digest,
                state,
                generation,
            },
        );
        self.directory_objects.push(DirectoryObjectRecord {
            id: directory_object,
            file_object,
            file_object_generation,
            namespace: namespace.to_string(),
            directory_key: directory_key.to_string(),
            directory_path: directory_path.to_string(),
            entry_name: entry_name.to_string(),
            child_file_key: child_file_key.to_string(),
            child_path: child_path.to_string(),
            entry_kind,
            file_size,
            content_digest,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn directory_objects(&self) -> &[DirectoryObjectRecord] {
        &self.directory_objects
    }

    pub fn directory_object_count(&self) -> usize {
        self.directory_objects.len()
    }

    pub fn check_directory_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.directory_objects {
            let Some(source) = self.file_objects.iter().find(|file| {
                file.id == record.file_object && file.generation == record.file_object_generation
            }) else {
                return Err(SemanticInvariantError::DirectoryObjectMissingFileObject {
                    directory_object: record.id,
                    file_object: record.file_object,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.file_object_generation == 0
                || record.namespace.is_empty()
                || record.directory_key.is_empty()
                || record.directory_path.is_empty()
                || record.entry_name.is_empty()
                || record.child_file_key.is_empty()
                || record.child_path.is_empty()
                || record.entry_kind != DirectoryEntryKind::File
                || record.file_size == 0
                || record.content_digest == 0
                || record.state == DirectoryObjectState::Invalidated
                || source.state == FileObjectState::Invalidated
                || record.namespace != source.namespace
                || record.child_file_key != source.file_key
                || record.child_path != source.path
                || record.file_size != source.file_size
                || record.content_digest != source.content_digest
            {
                return Err(SemanticInvariantError::DirectoryObjectInvalid {
                    directory_object: record.id,
                });
            }
            if let Some(duplicate) = self.directory_objects.iter().find(|other| {
                other.id != record.id
                    && other.state != DirectoryObjectState::Invalidated
                    && other.namespace == record.namespace
                    && other.directory_key == record.directory_key
                    && other.entry_name == record.entry_name
            }) {
                return Err(SemanticInvariantError::DirectoryObjectDuplicateEntry {
                    directory_object: duplicate.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DirectoryObjectRecorded {
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
                            generation,
                        } if *directory_object == record.id
                            && *file_object == record.file_object
                            && *file_object_generation == record.file_object_generation
                            && namespace == &record.namespace
                            && directory_key == &record.directory_key
                            && directory_path == &record.directory_path
                            && entry_name == &record.entry_name
                            && child_file_key == &record.child_file_key
                            && child_path == &record.child_path
                            && *entry_kind == record.entry_kind
                            && *file_size == record.file_size
                            && *content_digest == record.content_digest
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DirectoryObjectMissingEvent {
                    directory_object: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_directory_object_file_generation_for_test(
        &mut self,
        directory_object: DirectoryObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.directory_objects.iter_mut().find(|record| record.id == directory_object)
        {
            record.file_object_generation = generation;
        }
    }
}
