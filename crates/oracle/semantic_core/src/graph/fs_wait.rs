use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_fs_wait(
        &self,
        fs_wait: FsWaitId,
        wait: WaitId,
        wait_generation: Generation,
        file_handle_capability: FileHandleCapabilityId,
        file_handle_capability_generation: Generation,
        operation: &str,
        sequence: u64,
    ) -> Result<&FileHandleCapabilityRecord, &'static str> {
        if fs_wait == 0 {
            return Err("fs wait id=0 is invalid");
        }
        if self.domains.block.fs_waits.iter().any(|record| record.id == fs_wait) {
            return Err("fs wait already exists");
        }
        if wait_generation == 0
            || file_handle_capability_generation == 0
            || operation.is_empty()
            || sequence == 0
        {
            return Err("fs wait identity values must be nonzero");
        }
        let Some(capability_record) =
            self.domains.block.file_handle_capabilities.iter().find(|record| {
                record.id == file_handle_capability
                    && record.generation == file_handle_capability_generation
                    && record.state == FileHandleCapabilityState::Allowed
            })
        else {
            return Err("fs wait file handle capability generation is missing or not allowed");
        };
        if capability_record.operation != operation {
            return Err("fs wait operation does not match file handle capability");
        }
        let expected_blocker = capability_record.object_ref();
        let expected_wait_kind = match operation {
            "read" => SemanticWaitKind::FdReadable,
            "write" => SemanticWaitKind::FdWritable,
            _ => return Err("fs wait operation is unsupported"),
        };
        let Some(wait_record) = self.domains.wait.waits.iter().find(|record| {
            record.id == wait
                && record.generation == wait_generation
                && record.state == WaitState::Pending
        }) else {
            return Err("fs wait token generation is missing or not pending");
        };
        if wait_record.kind != expected_wait_kind
            || !wait_record.blockers.contains(&expected_blocker)
        {
            return Err("fs wait token does not reference the file handle capability");
        }
        if wait_record.owner_store != Some(capability_record.owner_store)
            || wait_record.owner_store_generation != Some(capability_record.owner_store_generation)
        {
            return Err("fs wait owner store does not match file handle capability");
        }
        if !self.domains.lifecycle.stores.iter().any(|record| {
            record.id == capability_record.owner_store
                && record.generation == capability_record.owner_store_generation
                && record.state != StoreState::Dead
        }) {
            return Err("fs wait owner store generation is missing or dead");
        }
        if self.domains.block.fs_waits.iter().any(|record| {
            record.wait == wait
                && record.wait_generation == wait_generation
                && record.state == FsWaitState::Pending
        }) {
            return Err("fs wait token already has a pending fs wait");
        }
        if self.domains.block.fs_waits.iter().any(|record| {
            record.owner_store == capability_record.owner_store
                && record.owner_store_generation == capability_record.owner_store_generation
                && record.file_handle_capability == file_handle_capability
                && record.file_handle_capability_generation == file_handle_capability_generation
                && record.operation == operation
                && record.sequence == sequence
                && record.state == FsWaitState::Pending
        }) {
            return Err("fs wait already pending for file handle operation sequence");
        }
        if self.check_invariants().is_err() {
            return Err("fs wait requires invariant-clean graph");
        }
        Ok(capability_record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_fs_wait_with_id(
        &mut self,
        fs_wait: FsWaitId,
        wait: WaitId,
        wait_generation: Generation,
        file_handle_capability: FileHandleCapabilityId,
        file_handle_capability_generation: Generation,
        operation: &str,
        sequence: u64,
        note: &str,
    ) -> bool {
        let Ok(capability_snapshot) = self
            .validate_fs_wait(
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                sequence,
            )
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.domains.block.next_fs_wait_id =
            self.domains.block.next_fs_wait_id.max(fs_wait.saturating_add(1));
        let blocker = capability_snapshot.object_ref();
        let created_at_event = self.event_log.push(
            "block",
            EventKind::FsWaitCreated {
                fs_wait,
                wait,
                wait_generation,
                owner_store: capability_snapshot.owner_store,
                owner_store_generation: capability_snapshot.owner_store_generation,
                file_object: capability_snapshot.file_object,
                file_object_generation: capability_snapshot.file_object_generation,
                directory_object: capability_snapshot.directory_object,
                directory_object_generation: capability_snapshot.directory_object_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation: operation.to_string(),
                blocker,
                sequence,
                byte_len: capability_snapshot.byte_len,
                generation,
            },
        );
        self.domains.block.fs_waits.push(FsWaitRecord {
            id: fs_wait,
            wait,
            wait_generation,
            owner_store: capability_snapshot.owner_store,
            owner_store_generation: capability_snapshot.owner_store_generation,
            file_object: capability_snapshot.file_object,
            file_object_generation: capability_snapshot.file_object_generation,
            directory_object: capability_snapshot.directory_object,
            directory_object_generation: capability_snapshot.directory_object_generation,
            file_handle_capability,
            file_handle_capability_generation,
            operation: operation.to_string(),
            blocker,
            sequence,
            byte_len: capability_snapshot.byte_len,
            generation,
            state: FsWaitState::Pending,
            created_at_event,
            completed_at_event: None,
            cancel_reason: None,
            note: note.to_string(),
        });
        true
    }

    pub fn resolve_fs_wait(
        &mut self,
        fs_wait: FsWaitId,
        fs_wait_generation: Generation,
        note: &str,
    ) -> bool {
        let Some(index) = self.domains.block.fs_waits.iter().position(|record| {
            record.id == fs_wait
                && record.generation == fs_wait_generation
                && record.state == FsWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.block.fs_waits[index].clone();
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_resolved(record.wait, "fs-ready");
        let completed_at_event = self.event_log.push(
            "block",
            EventKind::FsWaitResolved {
                fs_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                generation: fs_wait_generation,
            },
        );
        self.domains.block.fs_waits[index].state = FsWaitState::Resolved;
        self.domains.block.fs_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.block.fs_waits[index].note = note.to_string();
        true
    }

    pub fn cancel_fs_wait(
        &mut self,
        fs_wait: FsWaitId,
        fs_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: &str,
    ) -> bool {
        if !matches!(
            reason,
            WaitCancelReason::CloseFd
                | WaitCancelReason::StoreFault
                | WaitCancelReason::CapabilityRevoked
                | WaitCancelReason::ResourceDropped
                | WaitCancelReason::GenerationMismatch
        ) {
            return false;
        }
        let Some(index) = self.domains.block.fs_waits.iter().position(|record| {
            record.id == fs_wait
                && record.generation == fs_wait_generation
                && record.state == FsWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.block.fs_waits[index].clone();
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_cancelled_with_reason(record.wait, errno, reason);
        let completed_at_event = self.event_log.push(
            "block",
            EventKind::FsWaitCancelled {
                fs_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                reason,
                generation: fs_wait_generation,
            },
        );
        self.domains.block.fs_waits[index].state = FsWaitState::Cancelled;
        self.domains.block.fs_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.block.fs_waits[index].cancel_reason = Some(reason);
        self.domains.block.fs_waits[index].note = note.to_string();
        true
    }

    pub fn fs_waits(&self) -> &[FsWaitRecord] {
        &self.domains.block.fs_waits
    }

    pub fn fs_wait_count(&self) -> usize {
        self.domains.block.fs_waits.len()
    }

    pub fn check_fs_wait_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.fs_waits {
            let Some(wait_record) =
                self.domains.wait.waits.iter().find(|wait| {
                    wait.id == record.wait && wait.generation == record.wait_generation
                })
            else {
                return Err(SemanticInvariantError::FsWaitMissingWait {
                    fs_wait: record.id,
                    wait: record.wait,
                });
            };
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FsWaitMissingStore {
                    fs_wait: record.id,
                    store: record.owner_store,
                });
            };
            let Some(file_record) = self.domains.block.file_objects.iter().find(|file| {
                file.id == record.file_object && file.generation == record.file_object_generation
            }) else {
                return Err(SemanticInvariantError::FsWaitMissingFileObject {
                    fs_wait: record.id,
                    file_object: record.file_object,
                });
            };
            let Some(directory_record) =
                self.domains.block.directory_objects.iter().find(|directory| {
                    directory.id == record.directory_object
                        && directory.generation == record.directory_object_generation
                })
            else {
                return Err(SemanticInvariantError::FsWaitMissingDirectoryObject {
                    fs_wait: record.id,
                    directory_object: record.directory_object,
                });
            };
            let Some(capability_record) =
                self.domains.block.file_handle_capabilities.iter().find(|capability| {
                    capability.id == record.file_handle_capability
                        && capability.generation == record.file_handle_capability_generation
                })
            else {
                return Err(SemanticInvariantError::FsWaitMissingFileHandleCapability {
                    fs_wait: record.id,
                    file_handle_capability: record.file_handle_capability,
                });
            };
            let expected_kind = match record.operation.as_str() {
                "read" => SemanticWaitKind::FdReadable,
                "write" => SemanticWaitKind::FdWritable,
                _ => return Err(SemanticInvariantError::FsWaitInvalid { fs_wait: record.id }),
            };
            if record.id == 0
                || record.generation == 0
                || record.wait_generation == 0
                || record.owner_store_generation == 0
                || record.file_object_generation == 0
                || record.directory_object_generation == 0
                || record.file_handle_capability_generation == 0
                || record.sequence == 0
                || record.byte_len == 0
                || store_record.state == StoreState::Dead
                || file_record.state == FileObjectState::Invalidated
                || directory_record.state == DirectoryObjectState::Invalidated
                || directory_record.file_object != record.file_object
                || directory_record.file_object_generation != record.file_object_generation
                || capability_record.owner_store != record.owner_store
                || capability_record.owner_store_generation != record.owner_store_generation
                || capability_record.file_object != record.file_object
                || capability_record.file_object_generation != record.file_object_generation
                || capability_record.directory_object != record.directory_object
                || capability_record.directory_object_generation
                    != record.directory_object_generation
                || capability_record.operation != record.operation
                || capability_record.byte_len != record.byte_len
                || capability_record.state != FileHandleCapabilityState::Allowed
                || record.blocker != capability_record.object_ref()
                || wait_record.kind != expected_kind
                || !wait_record.blockers.contains(&record.blocker)
                || wait_record.owner_store != Some(record.owner_store)
                || wait_record.owner_store_generation != Some(record.owner_store_generation)
            {
                return Err(SemanticInvariantError::FsWaitInvalid { fs_wait: record.id });
            }
            if record.state == FsWaitState::Pending
                && self.domains.block.fs_waits.iter().any(|other| {
                    other.id != record.id
                        && other.wait == record.wait
                        && other.wait_generation == record.wait_generation
                        && other.state == FsWaitState::Pending
                })
            {
                return Err(SemanticInvariantError::FsWaitDuplicateWait {
                    fs_wait: record.id,
                    wait: record.wait,
                });
            }
            match record.state {
                FsWaitState::Pending => {
                    if wait_record.state != WaitState::Pending {
                        return Err(SemanticInvariantError::FsWaitInvalid { fs_wait: record.id });
                    }
                }
                FsWaitState::Resolved => {
                    if !matches!(wait_record.state, WaitState::Resolved | WaitState::Consumed)
                        || record.cancel_reason.is_some()
                    {
                        return Err(SemanticInvariantError::FsWaitInvalid { fs_wait: record.id });
                    }
                }
                FsWaitState::Cancelled => {
                    if wait_record.state != WaitState::Cancelled
                        || wait_record.cancel_reason != record.cancel_reason
                        || record.cancel_reason.is_none()
                    {
                        return Err(SemanticInvariantError::FsWaitInvalid { fs_wait: record.id });
                    }
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FsWaitCreated {
                            fs_wait,
                            wait,
                            wait_generation,
                            owner_store,
                            owner_store_generation,
                            file_object,
                            file_object_generation,
                            directory_object,
                            directory_object_generation,
                            file_handle_capability,
                            file_handle_capability_generation,
                            operation,
                            blocker,
                            sequence,
                            byte_len,
                            generation,
                        } if *fs_wait == record.id
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *file_object == record.file_object
                            && *file_object_generation == record.file_object_generation
                            && *directory_object == record.directory_object
                            && *directory_object_generation == record.directory_object_generation
                            && *file_handle_capability == record.file_handle_capability
                            && *file_handle_capability_generation == record.file_handle_capability_generation
                            && operation == &record.operation
                            && *blocker == record.blocker
                            && *sequence == record.sequence
                            && *byte_len == record.byte_len
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FsWaitMissingEvent {
                    fs_wait: record.id,
                    event: record.created_at_event,
                });
            }
            if let Some(completed_at_event) = record.completed_at_event {
                let found = self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && match (&record.state, &event.kind) {
                            (
                                FsWaitState::Resolved,
                                EventKind::FsWaitResolved {
                                    fs_wait,
                                    wait,
                                    wait_generation,
                                    generation,
                                },
                            ) => {
                                *fs_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && *generation == record.generation
                            }
                            (
                                FsWaitState::Cancelled,
                                EventKind::FsWaitCancelled {
                                    fs_wait,
                                    wait,
                                    wait_generation,
                                    reason,
                                    generation,
                                },
                            ) => {
                                *fs_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*reason) == record.cancel_reason
                                    && *generation == record.generation
                            }
                            _ => false,
                        }
                });
                if !found {
                    return Err(SemanticInvariantError::FsWaitMissingEvent {
                        fs_wait: record.id,
                        event: completed_at_event,
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_fs_wait_file_handle_generation_for_test(
        &mut self,
        fs_wait: FsWaitId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.block.fs_waits.iter_mut().find(|record| record.id == fs_wait)
        {
            record.file_handle_capability_generation = generation;
        }
    }
}
