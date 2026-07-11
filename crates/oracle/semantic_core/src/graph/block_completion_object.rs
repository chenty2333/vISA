use super::*;

impl SemanticGraph {
    pub(crate) fn validate_block_completion_object(
        &self,
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        status: BlockCompletionStatus,
    ) -> Result<&BlockRequestObjectRecord, &'static str> {
        if block_completion == 0 {
            return Err("block completion object id=0 is invalid");
        }
        if self
            .domains
            .block
            .block_completion_objects
            .iter()
            .any(|record| record.id == block_completion)
        {
            return Err("block completion object already exists");
        }
        if block_request_generation == 0 || sequence == 0 {
            return Err("block completion object identity values must be nonzero");
        }
        let Some(request_record) = self.domains.block.block_request_objects.iter().find(|record| {
            record.id == block_request && record.generation == block_request_generation
        }) else {
            return Err("block completion object block request generation is missing");
        };
        if self.domains.block.block_completion_objects.iter().any(|record| {
            record.block_request == block_request
                && record.block_request_generation == block_request_generation
                && record.state == BlockCompletionObjectState::Recorded
        }) {
            return Err("block completion object already exists for block request generation");
        }
        if request_record.state != BlockRequestObjectState::Submitted {
            return Err("block completion object block request is not submitted");
        }
        if request_record.sequence != sequence {
            return Err("block completion object sequence does not match block request");
        }
        if status == BlockCompletionStatus::Success && completed_bytes != request_record.byte_len {
            return Err("block completion object success must complete the full byte range");
        }
        if completed_bytes > request_record.byte_len {
            return Err("block completion object completed bytes exceed request byte length");
        }
        if status == BlockCompletionStatus::IoError && completed_bytes == request_record.byte_len {
            return Err("block completion object io-error must leave an incomplete byte range");
        }
        if self.check_invariants().is_err() {
            return Err("block completion object requires invariant-clean graph");
        }
        Ok(request_record)
    }

    pub fn record_block_completion_object_with_id(
        &mut self,
        block_completion: BlockCompletionObjectId,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        sequence: u64,
        completed_bytes: u64,
        status: BlockCompletionStatus,
        note: &str,
    ) -> bool {
        let Ok(request_snapshot) = self
            .validate_block_completion_object(
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
            )
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.domains.block.next_block_completion_object_id = self
            .domains
            .block
            .next_block_completion_object_id
            .max(block_completion.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockCompletionObjectRecorded {
                block_completion,
                block_request,
                block_request_generation,
                block_device: request_snapshot.block_device,
                block_device_generation: request_snapshot.block_device_generation,
                block_range: request_snapshot.block_range,
                block_range_generation: request_snapshot.block_range_generation,
                sequence,
                completed_bytes,
                status,
                generation,
            },
        );
        if let Some(request_record) =
            self.domains.block.block_request_objects.iter_mut().find(|record| {
                record.id == block_request && record.generation == block_request_generation
            })
        {
            request_record.state = BlockRequestObjectState::Completed;
        }
        self.domains.block.block_completion_objects.push(BlockCompletionObjectRecord {
            id: block_completion,
            block_request,
            block_request_generation,
            block_device: request_snapshot.block_device,
            block_device_generation: request_snapshot.block_device_generation,
            block_range: request_snapshot.block_range,
            block_range_generation: request_snapshot.block_range_generation,
            sequence,
            completed_bytes,
            status,
            generation,
            state: BlockCompletionObjectState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_completion_objects(&self) -> &[BlockCompletionObjectRecord] {
        &self.domains.block.block_completion_objects
    }

    pub fn block_completion_object_count(&self) -> usize {
        self.domains.block.block_completion_objects.len()
    }

    pub fn check_block_completion_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.block_completion_objects {
            let Some(request_record) =
                self.domains.block.block_request_objects.iter().find(|request| {
                    request.id == record.block_request
                        && request.generation == record.block_request_generation
                })
            else {
                return Err(SemanticInvariantError::BlockCompletionObjectMissingRequest {
                    block_completion: record.id,
                    block_request: record.block_request,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.block_request_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.sequence == 0
                || record.state != BlockCompletionObjectState::Recorded
                || request_record.state != BlockRequestObjectState::Completed
                || request_record.block_device != record.block_device
                || request_record.block_device_generation != record.block_device_generation
                || request_record.block_range != record.block_range
                || request_record.block_range_generation != record.block_range_generation
                || request_record.sequence != record.sequence
                || record.completed_bytes > request_record.byte_len
                || (record.status == BlockCompletionStatus::Success
                    && record.completed_bytes != request_record.byte_len)
                || (record.status == BlockCompletionStatus::IoError
                    && record.completed_bytes == request_record.byte_len)
            {
                return Err(SemanticInvariantError::BlockCompletionObjectInvalid {
                    block_completion: record.id,
                });
            }
            if let Some(duplicate) =
                self.domains.block.block_completion_objects.iter().find(|other| {
                    other.id != record.id
                        && other.block_request == record.block_request
                        && other.block_request_generation == record.block_request_generation
                        && other.state == BlockCompletionObjectState::Recorded
                })
            {
                return Err(SemanticInvariantError::BlockCompletionObjectDuplicateRequest {
                    block_completion: duplicate.id,
                    block_request: record.block_request,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockCompletionObjectRecorded {
                            block_completion,
                            block_request,
                            block_request_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            sequence,
                            completed_bytes,
                            status,
                            generation,
                        } if *block_completion == record.id
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *sequence == record.sequence
                            && *completed_bytes == record.completed_bytes
                            && *status == record.status
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockCompletionObjectMissingEvent {
                    block_completion: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_completion_request_generation_for_test(
        &mut self,
        block_completion: BlockCompletionObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .block
            .block_completion_objects
            .iter_mut()
            .find(|record| record.id == block_completion)
        {
            record.block_request_generation = generation;
        }
    }
}
