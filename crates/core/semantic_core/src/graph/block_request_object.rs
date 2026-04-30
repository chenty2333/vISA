use super::*;

impl SemanticGraph {
    pub(crate) fn validate_block_request_object(
        &self,
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        operation: BlockRequestOperation,
        sequence: u64,
    ) -> Result<u64, &'static str> {
        if block_request == 0 {
            return Err("block request object id=0 is invalid");
        }
        if self.domains.block.block_request_objects.iter().any(|record| record.id == block_request)
        {
            return Err("block request object already exists");
        }
        if block_device_generation == 0 || block_range_generation == 0 || sequence == 0 {
            return Err("block request object identity values must be nonzero");
        }
        let Some(block_device_record) =
            self.domains.block.block_device_objects.iter().find(|record| {
                record.id == block_device
                    && record.generation == block_device_generation
                    && record.state == BlockDeviceObjectState::Registered
            })
        else {
            return Err("block request object block device generation is missing or inactive");
        };
        let Some(block_range_record) =
            self.domains.block.block_range_objects.iter().find(|record| {
                record.id == block_range
                    && record.generation == block_range_generation
                    && record.state == BlockRangeObjectState::Registered
            })
        else {
            return Err("block request object block range generation is missing or inactive");
        };
        if block_range_record.block_device != block_device_record.id
            || block_range_record.block_device_generation != block_device_generation
        {
            return Err("block request object range and block device mismatch");
        }
        if operation == BlockRequestOperation::Write && block_device_record.read_only {
            return Err("block request object write denied on read-only block device");
        }
        if self.domains.block.block_request_objects.iter().any(|record| {
            record.block_device == block_device
                && record.block_device_generation == block_device_generation
                && record.sequence == sequence
                && record.state == BlockRequestObjectState::Submitted
        }) {
            return Err("block request object sequence already exists for block device generation");
        }
        if self.check_invariants().is_err() {
            return Err("block request object requires invariant-clean graph");
        }
        Ok(block_range_record.byte_len)
    }

    pub fn record_block_request_object_with_id(
        &mut self,
        block_request: BlockRequestObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        operation: BlockRequestOperation,
        sequence: u64,
        note: &str,
    ) -> bool {
        let Ok(byte_len) = self.validate_block_request_object(
            block_request,
            block_device,
            block_device_generation,
            block_range,
            block_range_generation,
            operation,
            sequence,
        ) else {
            return false;
        };
        let generation = 1;
        self.domains.block.next_block_request_object_id =
            self.domains.block.next_block_request_object_id.max(block_request.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockRequestObjectRecorded {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                byte_len,
                generation,
            },
        );
        self.domains.block.block_request_objects.push(BlockRequestObjectRecord {
            id: block_request,
            block_device,
            block_device_generation,
            block_range,
            block_range_generation,
            operation,
            sequence,
            byte_len,
            generation,
            state: BlockRequestObjectState::Submitted,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_request_objects(&self) -> &[BlockRequestObjectRecord] {
        &self.domains.block.block_request_objects
    }

    pub fn block_request_object_count(&self) -> usize {
        self.domains.block.block_request_objects.len()
    }

    pub fn check_block_request_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.block_request_objects {
            let Some(block_device_record) =
                self.domains.block.block_device_objects.iter().find(|block_device| {
                    block_device.id == record.block_device
                        && block_device.generation == record.block_device_generation
                })
            else {
                return Err(SemanticInvariantError::BlockRequestObjectMissingDevice {
                    block_request: record.id,
                    block_device: record.block_device,
                });
            };
            let Some(block_range_record) =
                self.domains.block.block_range_objects.iter().find(|block_range| {
                    block_range.id == record.block_range
                        && block_range.generation == record.block_range_generation
                })
            else {
                return Err(SemanticInvariantError::BlockRequestObjectMissingRange {
                    block_request: record.id,
                    block_range: record.block_range,
                });
            };
            let has_completion =
                self.domains.block.block_completion_objects.iter().any(|completion| {
                    completion.block_request == record.id
                        && completion.block_request_generation == record.generation
                        && completion.state == BlockCompletionObjectState::Recorded
                });
            if record.id == 0
                || record.generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.sequence == 0
                || record.byte_len == 0
                || block_device_record.state != BlockDeviceObjectState::Registered
                || block_range_record.state != BlockRangeObjectState::Registered
                || matches!(record.state, BlockRequestObjectState::Cancelled)
                || (record.state == BlockRequestObjectState::Completed && !has_completion)
                || (record.state == BlockRequestObjectState::Submitted && has_completion)
                || block_range_record.block_device != record.block_device
                || block_range_record.block_device_generation != record.block_device_generation
                || record.byte_len != block_range_record.byte_len
                || (record.operation == BlockRequestOperation::Write
                    && block_device_record.read_only)
            {
                return Err(SemanticInvariantError::BlockRequestObjectInvalid {
                    block_request: record.id,
                });
            }
            if let Some(duplicate) = self.domains.block.block_request_objects.iter().find(|other| {
                other.id != record.id
                    && other.block_device == record.block_device
                    && other.block_device_generation == record.block_device_generation
                    && other.sequence == record.sequence
                    && other.state == BlockRequestObjectState::Submitted
            }) {
                return Err(SemanticInvariantError::BlockRequestObjectDuplicateSequence {
                    block_request: duplicate.id,
                    block_device: record.block_device,
                    sequence: record.sequence,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockRequestObjectRecorded {
                            block_request,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            operation,
                            sequence,
                            byte_len,
                            generation,
                        } if *block_request == record.id
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *operation == record.operation
                            && *sequence == record.sequence
                            && *byte_len == record.byte_len
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockRequestObjectMissingEvent {
                    block_request: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_request_range_generation_for_test(
        &mut self,
        block_request: BlockRequestObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .block
            .block_request_objects
            .iter_mut()
            .find(|record| record.id == block_request)
        {
            record.block_range_generation = generation;
        }
    }
}
