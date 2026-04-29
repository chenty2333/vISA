use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_file_handle_capability(
        &self,
        file_handle_capability: FileHandleCapabilityId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle: &CapabilityHandle,
        operation: &str,
        file_offset: u64,
        byte_len: u64,
        content_digest: u64,
    ) -> Result<(), &'static str> {
        if file_handle_capability == 0 {
            return Err("file handle capability id=0 is invalid");
        }
        if self.file_handle_capabilities.iter().any(|record| record.id == file_handle_capability) {
            return Err("file handle capability already exists");
        }
        if owner_store_generation == 0
            || file_object_generation == 0
            || directory_object_generation == 0
            || capability_generation == 0
            || operation.is_empty()
            || byte_len == 0
            || content_digest == 0
        {
            return Err("file handle capability identity values must be nonzero");
        }
        if operation != "read" && operation != "write" {
            return Err("file handle capability operation is unsupported");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|record| record.id == owner_store && record.generation == owner_store_generation)
        else {
            return Err("file handle capability owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("file handle capability owner store is dead");
        }
        let Some(file_record) = self.file_objects.iter().find(|record| {
            record.id == file_object
                && record.generation == file_object_generation
                && record.state != FileObjectState::Invalidated
        }) else {
            return Err("file handle capability file generation is missing");
        };
        let Some(directory_record) = self.directory_objects.iter().find(|record| {
            record.id == directory_object
                && record.generation == directory_object_generation
                && record.state != DirectoryObjectState::Invalidated
        }) else {
            return Err("file handle capability directory generation is missing");
        };
        if directory_record.file_object != file_record.id
            || directory_record.file_object_generation != file_record.generation
            || directory_record.child_path != file_record.path
            || directory_record.content_digest != content_digest
            || file_record.content_digest != content_digest
            || file_offset.saturating_add(byte_len) > file_record.file_size
        {
            return Err("file handle capability file binding mismatch");
        }
        if handle.owner_store != owner_store
            || handle.owner_store_generation != owner_store_generation
            || handle.class_hint != CapabilityClass::FileHandle
            || !handle.rights_hint.contains(operation)
        {
            return Err("file handle capability handle mismatch");
        }
        let authority =
            AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_record.object_ref());
        let capability_record = self
            .capabilities
            .check_authority(&store_record.package, authority, operation, Some(handle))
            .map_err(|_| "file handle capability handle is not authorized")?;
        if capability_record.id != capability
            || capability_record.generation != capability_generation
        {
            return Err("file handle capability attribution mismatch");
        }
        if self.file_handle_capabilities.iter().any(|record| {
            record.owner_store == owner_store
                && record.owner_store_generation == owner_store_generation
                && record.file_object == file_object
                && record.file_object_generation == file_object_generation
                && record.operation == operation
                && record.state == FileHandleCapabilityState::Allowed
        }) {
            return Err("file handle capability already allowed for file operation");
        }
        if self.check_invariants().is_err() {
            return Err("file handle capability requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_file_handle_capability_with_id(
        &mut self,
        file_handle_capability: FileHandleCapabilityId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        file_object: FileObjectId,
        file_object_generation: Generation,
        directory_object: DirectoryObjectId,
        directory_object_generation: Generation,
        capability: CapabilityId,
        capability_generation: Generation,
        handle: CapabilityHandle,
        operation: &str,
        file_offset: u64,
        byte_len: u64,
        content_digest: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_file_handle_capability(
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                &handle,
                operation,
                file_offset,
                byte_len,
                content_digest,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_file_handle_capability_id =
            self.next_file_handle_capability_id.max(file_handle_capability.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::FileHandleCapabilityRecorded {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle_slot: handle.slot,
                handle_generation: handle.generation,
                handle_tag: handle.tag,
                operation: operation.to_string(),
                file_offset,
                byte_len,
                content_digest,
                state: FileHandleCapabilityState::Allowed,
                generation,
            },
        );
        self.file_handle_capabilities.push(FileHandleCapabilityRecord {
            id: file_handle_capability,
            owner_store,
            owner_store_generation,
            file_object,
            file_object_generation,
            directory_object,
            directory_object_generation,
            capability,
            capability_generation,
            handle_slot: handle.slot,
            handle_generation: handle.generation,
            handle_tag: handle.tag,
            operation: operation.to_string(),
            file_offset,
            byte_len,
            content_digest,
            generation,
            state: FileHandleCapabilityState::Allowed,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn file_handle_capabilities(&self) -> &[FileHandleCapabilityRecord] {
        &self.file_handle_capabilities
    }

    pub fn file_handle_capability_count(&self) -> usize {
        self.file_handle_capabilities.len()
    }

    pub fn check_file_handle_capability_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.file_handle_capabilities {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FileHandleCapabilityMissingStore {
                    file_handle_capability: record.id,
                    store: record.owner_store,
                });
            };
            let Some(file_record) = self.file_objects.iter().find(|file| {
                file.id == record.file_object && file.generation == record.file_object_generation
            }) else {
                return Err(SemanticInvariantError::FileHandleCapabilityMissingFileObject {
                    file_handle_capability: record.id,
                    file_object: record.file_object,
                });
            };
            let Some(directory_record) = self.directory_objects.iter().find(|directory| {
                directory.id == record.directory_object
                    && directory.generation == record.directory_object_generation
            }) else {
                return Err(SemanticInvariantError::FileHandleCapabilityMissingDirectoryObject {
                    file_handle_capability: record.id,
                    directory_object: record.directory_object,
                });
            };
            let Some(capability_record) = self.capabilities.record(record.capability) else {
                return Err(SemanticInvariantError::FileHandleCapabilityMissingCapability {
                    file_handle_capability: record.id,
                    capability: record.capability,
                });
            };
            let authority =
                AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_record.object_ref());
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.file_object_generation == 0
                || record.directory_object_generation == 0
                || record.capability_generation == 0
                || record.byte_len == 0
                || record.content_digest == 0
                || record.state != FileHandleCapabilityState::Allowed
                || store_record.state == StoreState::Dead
                || file_record.state == FileObjectState::Invalidated
                || directory_record.state == DirectoryObjectState::Invalidated
                || directory_record.file_object != record.file_object
                || directory_record.file_object_generation != record.file_object_generation
                || directory_record.child_path != file_record.path
                || directory_record.content_digest != record.content_digest
                || file_record.content_digest != record.content_digest
                || record.file_offset.saturating_add(record.byte_len) > file_record.file_size
                || capability_record.id != record.capability
                || capability_record.generation != record.capability_generation
                || capability_record.revoked
                || capability_record.subject != store_record.package
                || capability_record.object_ref != Some(authority)
                || capability_record.owner_store != Some(record.owner_store)
                || capability_record.owner_store_generation != Some(record.owner_store_generation)
                || capability_record.handle_slot != record.handle_slot
                || capability_record.handle_generation != record.handle_generation
                || capability_record.handle_tag != record.handle_tag
                || capability_record.class != CapabilityClass::FileHandle
                || !capability_record.operations.contains(&record.operation)
                || (capability_record.class.requires_manifest_declaration()
                    && !capability_record.manifest_decl)
            {
                return Err(SemanticInvariantError::FileHandleCapabilityInvalid {
                    file_handle_capability: record.id,
                });
            }
            if let Some(duplicate) = self.file_handle_capabilities.iter().find(|other| {
                other.id != record.id
                    && other.owner_store == record.owner_store
                    && other.owner_store_generation == record.owner_store_generation
                    && other.file_object == record.file_object
                    && other.file_object_generation == record.file_object_generation
                    && other.operation == record.operation
                    && other.state == FileHandleCapabilityState::Allowed
            }) {
                return Err(SemanticInvariantError::FileHandleCapabilityDuplicateGrant {
                    file_handle_capability: duplicate.id,
                    file_object: duplicate.file_object,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FileHandleCapabilityRecorded {
                            file_handle_capability,
                            owner_store,
                            owner_store_generation,
                            file_object,
                            file_object_generation,
                            directory_object,
                            directory_object_generation,
                            capability,
                            capability_generation,
                            handle_slot,
                            handle_generation,
                            handle_tag,
                            operation,
                            file_offset,
                            byte_len,
                            content_digest,
                            state,
                            generation,
                        } if *file_handle_capability == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *file_object == record.file_object
                            && *file_object_generation == record.file_object_generation
                            && *directory_object == record.directory_object
                            && *directory_object_generation == record.directory_object_generation
                            && *capability == record.capability
                            && *capability_generation == record.capability_generation
                            && *handle_slot == record.handle_slot
                            && *handle_generation == record.handle_generation
                            && *handle_tag == record.handle_tag
                            && operation == &record.operation
                            && *file_offset == record.file_offset
                            && *byte_len == record.byte_len
                            && *content_digest == record.content_digest
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FileHandleCapabilityMissingEvent {
                    file_handle_capability: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_file_handle_capability_generation_for_test(
        &mut self,
        file_handle_capability: FileHandleCapabilityId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .file_handle_capabilities
            .iter_mut()
            .find(|record| record.id == file_handle_capability)
        {
            record.file_object_generation = generation;
        }
    }
}
