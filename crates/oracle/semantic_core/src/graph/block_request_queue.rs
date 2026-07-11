use alloc::vec::Vec;

use super::*;

impl SemanticGraph {
    pub(crate) fn validate_block_request_queue(
        &self,
        queue: BlockRequestQueueId,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        depth: u32,
        entries: &[BlockRequestQueueEntryRef],
    ) -> Result<Vec<BlockRequestQueueEntryRecord>, &'static str> {
        if queue == 0 {
            return Err("block request queue id=0 is invalid");
        }
        if self.domains.block.block_request_queues.iter().any(|record| record.id == queue) {
            return Err("block request queue already exists");
        }
        if backend.generation == 0 || block_device_generation == 0 {
            return Err("block request queue identity values must be nonzero");
        }
        if backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("block request queue backend kind is unsupported for B9");
        }
        if depth == 0 {
            return Err("block request queue depth is zero");
        }
        if entries.is_empty() {
            return Err("block request queue must record at least one request");
        }
        if entries.len() > depth as usize {
            return Err("block request queue depth exceeded");
        }
        let Some(backend_record) = self.domains.block.fake_block_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) else {
            return Err("block request queue backend generation is missing or inactive");
        };
        if backend_record.block_device != block_device
            || backend_record.block_device_generation != block_device_generation
        {
            return Err("block request queue backend does not target block device generation");
        }
        let Some(block_device_record) =
            self.domains.block.block_device_objects.iter().find(|record| {
                record.id == block_device
                    && record.generation == block_device_generation
                    && record.state == BlockDeviceObjectState::Registered
            })
        else {
            return Err("block request queue block device generation is missing or inactive");
        };
        if block_device_record.id != backend_record.block_device {
            return Err("block request queue block device does not match backend");
        }

        let mut records = Vec::new();
        for entry in entries {
            if entry.request == 0 || entry.request_generation == 0 {
                return Err("block request queue entry identity values must be nonzero");
            }
            if self.domains.block.block_request_queues.iter().any(|record| {
                record.state == BlockRequestQueueState::Active
                    && record.entries.iter().any(|existing| {
                        existing.request == entry.request
                            && existing.request_generation == entry.request_generation
                    })
            }) {
                return Err("block request queue request already belongs to an active queue");
            }
            let Some(request_record) =
                self.domains.block.block_request_objects.iter().find(|record| {
                    record.id == entry.request && record.generation == entry.request_generation
                })
            else {
                return Err("block request queue request generation is missing");
            };
            if request_record.block_device != block_device
                || request_record.block_device_generation != block_device_generation
            {
                return Err("block request queue request does not target queue block device");
            }
            if request_record.sequence == 0 || request_record.byte_len == 0 {
                return Err("block request queue request values are invalid");
            }
            if records.iter().any(|record: &BlockRequestQueueEntryRecord| {
                record.request == entry.request
                    && record.request_generation == entry.request_generation
            }) {
                return Err("block request queue request appears twice");
            }
            if records.iter().any(|record: &BlockRequestQueueEntryRecord| {
                record.sequence == request_record.sequence
            }) {
                return Err("block request queue sequence appears twice");
            }

            let (completion, completion_generation, state) =
                match (entry.completion, entry.completion_generation) {
                    (None, None) => {
                        if request_record.state != BlockRequestObjectState::Submitted {
                            return Err("block request queue pending request is not submitted");
                        }
                        (None, None, BlockRequestQueueEntryState::Pending)
                    }
                    (Some(completion), Some(completion_generation)) => {
                        if completion_generation == 0 {
                            return Err("block request queue completion generation is zero");
                        }
                        if request_record.state != BlockRequestObjectState::Completed {
                            return Err("block request queue completed request is not completed");
                        }
                        let Some(completion_record) =
                            self.domains.block.block_completion_objects.iter().find(|record| {
                                record.id == completion
                                    && record.generation == completion_generation
                            })
                        else {
                            return Err("block request queue completion generation is missing");
                        };
                        if completion_record.block_request != request_record.id
                            || completion_record.block_request_generation
                                != request_record.generation
                            || completion_record.block_device != block_device
                            || completion_record.block_device_generation != block_device_generation
                            || completion_record.block_range != request_record.block_range
                            || completion_record.block_range_generation
                                != request_record.block_range_generation
                            || completion_record.sequence != request_record.sequence
                            || completion_record.state != BlockCompletionObjectState::Recorded
                        {
                            return Err("block request queue completion does not match request");
                        }
                        (
                            Some(completion),
                            Some(completion_generation),
                            BlockRequestQueueEntryState::Completed,
                        )
                    }
                    _ => {
                        return Err(
                            "block request queue completion id/generation must be both present",
                        );
                    }
                };

            records.push(BlockRequestQueueEntryRecord {
                request: request_record.id,
                request_generation: request_record.generation,
                completion,
                completion_generation,
                sequence: request_record.sequence,
                operation: request_record.operation,
                byte_len: request_record.byte_len,
                state,
            });
        }
        records.sort_by_key(|entry| entry.sequence);
        if self.check_invariants().is_err() {
            return Err("block request queue requires invariant-clean graph");
        }
        Ok(records)
    }

    pub fn record_block_request_queue_with_id(
        &mut self,
        queue: BlockRequestQueueId,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        depth: u32,
        entries: &[BlockRequestQueueEntryRef],
        note: &str,
    ) -> bool {
        let Ok(entries) = self.validate_block_request_queue(
            queue,
            backend,
            block_device,
            block_device_generation,
            depth,
            entries,
        ) else {
            return false;
        };
        let generation = 1;
        let pending_count = entries
            .iter()
            .filter(|entry| entry.state == BlockRequestQueueEntryState::Pending)
            .count() as u32;
        let completed_count = entries
            .iter()
            .filter(|entry| entry.state == BlockRequestQueueEntryState::Completed)
            .count() as u32;
        let first_sequence = entries.first().map(|entry| entry.sequence).unwrap_or(0);
        let last_sequence = entries.last().map(|entry| entry.sequence).unwrap_or(0);
        self.domains.block.next_block_request_queue_id =
            self.domains.block.next_block_request_queue_id.max(queue.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockRequestQueueRecorded {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                request_count: entries.len() as u32,
                pending_count,
                completed_count,
                first_sequence,
                last_sequence,
                generation,
            },
        );
        self.domains.block.block_request_queues.push(BlockRequestQueueRecord {
            id: queue,
            backend,
            block_device,
            block_device_generation,
            depth,
            entries,
            pending_count,
            completed_count,
            first_sequence,
            last_sequence,
            generation,
            state: BlockRequestQueueState::Active,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_request_queues(&self) -> &[BlockRequestQueueRecord] {
        &self.domains.block.block_request_queues
    }

    pub fn block_request_queue_count(&self) -> usize {
        self.domains.block.block_request_queues.len()
    }

    pub fn check_block_request_queue_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.block_request_queues {
            let Some(backend_record) =
                self.domains.block.fake_block_backends.iter().find(|backend| {
                    record.backend.kind == ContractObjectKind::FakeBlockBackendObject
                        && backend.id == record.backend.id
                        && backend.generation == record.backend.generation
                })
            else {
                return Err(SemanticInvariantError::BlockRequestQueueMissingBackend {
                    queue: record.id,
                    backend: record.backend,
                });
            };
            let Some(block_device_record) =
                self.domains.block.block_device_objects.iter().find(|block_device| {
                    block_device.id == record.block_device
                        && block_device.generation == record.block_device_generation
                })
            else {
                return Err(SemanticInvariantError::BlockRequestQueueMissingBlockDevice {
                    queue: record.id,
                    block_device: record.block_device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.backend.generation == 0
                || record.block_device_generation == 0
                || record.depth == 0
                || record.entries.is_empty()
                || record.entries.len() > record.depth as usize
                || record.state != BlockRequestQueueState::Active
                || record.backend.kind != ContractObjectKind::FakeBlockBackendObject
                || backend_record.state != FakeBlockBackendObjectState::Bound
                || block_device_record.state != BlockDeviceObjectState::Registered
                || backend_record.block_device != record.block_device
                || backend_record.block_device_generation != record.block_device_generation
                || record.pending_count as usize
                    != record
                        .entries
                        .iter()
                        .filter(|entry| entry.state == BlockRequestQueueEntryState::Pending)
                        .count()
                || record.completed_count as usize
                    != record
                        .entries
                        .iter()
                        .filter(|entry| entry.state == BlockRequestQueueEntryState::Completed)
                        .count()
                || record.entries.len() != (record.pending_count + record.completed_count) as usize
                || record.first_sequence == 0
                || record.last_sequence < record.first_sequence
            {
                return Err(SemanticInvariantError::BlockRequestQueueInvalid { queue: record.id });
            }
            for (index, entry) in record.entries.iter().enumerate() {
                let Some(request_record) =
                    self.domains.block.block_request_objects.iter().find(|request| {
                        request.id == entry.request
                            && request.generation == entry.request_generation
                    })
                else {
                    return Err(SemanticInvariantError::BlockRequestQueueMissingRequest {
                        queue: record.id,
                        block_request: entry.request,
                    });
                };
                if entry.request == 0
                    || entry.request_generation == 0
                    || entry.sequence == 0
                    || entry.byte_len == 0
                    || request_record.block_device != record.block_device
                    || request_record.block_device_generation != record.block_device_generation
                    || request_record.sequence != entry.sequence
                    || request_record.operation != entry.operation
                    || request_record.byte_len != entry.byte_len
                    || (entry.state == BlockRequestQueueEntryState::Pending
                        && (entry.completion.is_some()
                            || entry.completion_generation.is_some()
                            || request_record.state != BlockRequestObjectState::Submitted))
                    || (entry.state == BlockRequestQueueEntryState::Completed
                        && (entry.completion.is_none()
                            || entry.completion_generation.is_none()
                            || request_record.state != BlockRequestObjectState::Completed))
                {
                    return Err(SemanticInvariantError::BlockRequestQueueInvalid {
                        queue: record.id,
                    });
                }
                if let Some(completion) = entry.completion {
                    let Some(completion_generation) = entry.completion_generation else {
                        return Err(SemanticInvariantError::BlockRequestQueueInvalid {
                            queue: record.id,
                        });
                    };
                    let Some(completion_record) =
                        self.domains.block.block_completion_objects.iter().find(|record| {
                            record.id == completion && record.generation == completion_generation
                        })
                    else {
                        return Err(SemanticInvariantError::BlockRequestQueueMissingCompletion {
                            queue: record.id,
                            block_completion: completion,
                        });
                    };
                    if completion_record.block_request != request_record.id
                        || completion_record.block_request_generation != request_record.generation
                        || completion_record.block_device != record.block_device
                        || completion_record.block_device_generation
                            != record.block_device_generation
                        || completion_record.sequence != entry.sequence
                        || completion_record.state != BlockCompletionObjectState::Recorded
                    {
                        return Err(SemanticInvariantError::BlockRequestQueueInvalid {
                            queue: record.id,
                        });
                    }
                }
                if record.entries.iter().skip(index + 1).any(|other| {
                    other.request == entry.request
                        && other.request_generation == entry.request_generation
                }) {
                    return Err(SemanticInvariantError::BlockRequestQueueDuplicateRequest {
                        queue: record.id,
                        block_request: entry.request,
                    });
                }
                if record
                    .entries
                    .iter()
                    .skip(index + 1)
                    .any(|other| other.sequence == entry.sequence)
                {
                    return Err(SemanticInvariantError::BlockRequestQueueDuplicateSequence {
                        queue: record.id,
                        sequence: entry.sequence,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockRequestQueueRecorded {
                            queue,
                            backend,
                            block_device,
                            block_device_generation,
                            depth,
                            request_count,
                            pending_count,
                            completed_count,
                            first_sequence,
                            last_sequence,
                            generation,
                        } if *queue == record.id
                            && *backend == record.backend
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *depth == record.depth
                            && *request_count == record.entries.len() as u32
                            && *pending_count == record.pending_count
                            && *completed_count == record.completed_count
                            && *first_sequence == record.first_sequence
                            && *last_sequence == record.last_sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockRequestQueueMissingEvent {
                    queue: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_request_queue_backend_generation_for_test(
        &mut self,
        queue: BlockRequestQueueId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.block.block_request_queues.iter_mut().find(|record| record.id == queue)
        {
            record.backend.generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_request_queue_pending_count_for_test(
        &mut self,
        queue: BlockRequestQueueId,
        pending_count: u32,
    ) {
        if let Some(record) =
            self.domains.block.block_request_queues.iter_mut().find(|record| record.id == queue)
        {
            record.pending_count = pending_count;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_request_queue_block_device_generation_for_test(
        &mut self,
        queue: BlockRequestQueueId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.block.block_request_queues.iter_mut().find(|record| record.id == queue)
        {
            record.block_device_generation = generation;
        }
    }
}
