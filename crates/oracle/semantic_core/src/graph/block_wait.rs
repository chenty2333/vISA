use super::*;

impl SemanticGraph {
    pub(crate) fn validate_block_wait(
        &self,
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
    ) -> Result<&BlockRequestObjectRecord, &'static str> {
        if block_wait == 0 {
            return Err("block wait id=0 is invalid");
        }
        if self.domains.block.block_waits.iter().any(|record| record.id == block_wait) {
            return Err("block wait already exists");
        }
        if wait_generation == 0 || block_request_generation == 0 {
            return Err("block wait identity values must be nonzero");
        }
        let request_ref = ContractObjectRef::new(
            ContractObjectKind::BlockRequestObject,
            block_request,
            block_request_generation,
        );
        let Some(wait_record) = self.domains.wait.waits.iter().find(|record| {
            record.id == wait
                && record.generation == wait_generation
                && record.state == WaitState::Pending
        }) else {
            return Err("block wait token generation is missing or not pending");
        };
        if wait_record.kind != SemanticWaitKind::DriverCompletion
            || !wait_record.blockers.contains(&request_ref)
        {
            return Err("block wait token does not reference the requested block request");
        }
        if let Some(store) = wait_record.owner_store {
            let Some(generation) = wait_record.owner_store_generation else {
                return Err("block wait owner store generation is missing");
            };
            let Some(store_record) = self
                .domains
                .lifecycle
                .stores
                .iter()
                .find(|record| record.id == store && record.generation == generation)
            else {
                return Err("block wait owner store generation is missing");
            };
            if store_record.state == StoreState::Dead {
                return Err("block wait owner store is dead");
            }
        }
        let Some(request_record) = self.domains.block.block_request_objects.iter().find(|record| {
            record.id == block_request
                && record.generation == block_request_generation
                && record.state == BlockRequestObjectState::Submitted
        }) else {
            return Err("block wait request generation is missing or not submitted");
        };
        if self.domains.block.block_waits.iter().any(|record| {
            record.wait == wait
                && record.wait_generation == wait_generation
                && record.state == BlockWaitState::Pending
        }) {
            return Err("block wait token already has a pending block wait");
        }
        if self.domains.block.block_waits.iter().any(|record| {
            record.block_request == block_request
                && record.block_request_generation == block_request_generation
                && record.state == BlockWaitState::Pending
        }) {
            return Err("block request already has a pending block wait");
        }
        if self.check_invariants().is_err() {
            return Err("block wait requires invariant-clean graph");
        }
        Ok(request_record)
    }

    pub fn record_block_wait_with_id(
        &mut self,
        block_wait: BlockWaitId,
        wait: WaitId,
        wait_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        note: &str,
    ) -> bool {
        let Ok(request_snapshot) = self
            .validate_block_wait(
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
            )
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.domains.block.next_block_wait_id =
            self.domains.block.next_block_wait_id.max(block_wait.saturating_add(1));
        let created_at_event = self.event_log.push(
            "block",
            EventKind::BlockWaitCreated {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                block_device: request_snapshot.block_device,
                block_device_generation: request_snapshot.block_device_generation,
                block_range: request_snapshot.block_range,
                block_range_generation: request_snapshot.block_range_generation,
                operation: request_snapshot.operation,
                sequence: request_snapshot.sequence,
                byte_len: request_snapshot.byte_len,
                generation,
            },
        );
        self.domains.block.block_waits.push(BlockWaitRecord {
            id: block_wait,
            wait,
            wait_generation,
            block_request,
            block_request_generation,
            block_device: request_snapshot.block_device,
            block_device_generation: request_snapshot.block_device_generation,
            block_range: request_snapshot.block_range,
            block_range_generation: request_snapshot.block_range_generation,
            operation: request_snapshot.operation,
            sequence: request_snapshot.sequence,
            byte_len: request_snapshot.byte_len,
            generation,
            state: BlockWaitState::Pending,
            created_at_event,
            completed_at_event: None,
            completion: None,
            completion_generation: None,
            cancel_reason: None,
            note: note.to_string(),
        });
        true
    }

    pub fn resolve_block_wait_with_completion(
        &mut self,
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        note: &str,
    ) -> bool {
        let Some(index) = self.domains.block.block_waits.iter().position(|record| {
            record.id == block_wait
                && record.generation == block_wait_generation
                && record.state == BlockWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.block.block_waits[index].clone();
        let Some(completion) =
            self.domains.block.block_completion_objects.iter().find(|completion| {
                completion.id == block_completion
                    && completion.generation == block_completion_generation
                    && completion.state == BlockCompletionObjectState::Recorded
            })
        else {
            return false;
        };
        if completion.block_request != record.block_request
            || completion.block_request_generation != record.block_request_generation
            || completion.block_device != record.block_device
            || completion.block_device_generation != record.block_device_generation
            || completion.block_range != record.block_range
            || completion.block_range_generation != record.block_range_generation
            || completion.sequence != record.sequence
            || completion.status != BlockCompletionStatus::Success
            || completion.completed_bytes != record.byte_len
        {
            return false;
        }
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_resolved(record.wait, "block-completion");
        let completed_at_event = self.event_log.push(
            "block",
            EventKind::BlockWaitResolved {
                block_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                block_completion,
                block_completion_generation,
                generation: block_wait_generation,
            },
        );
        self.domains.block.block_waits[index].state = BlockWaitState::Resolved;
        self.domains.block.block_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.block.block_waits[index].completion = Some(block_completion);
        self.domains.block.block_waits[index].completion_generation =
            Some(block_completion_generation);
        self.domains.block.block_waits[index].note = note.to_string();
        true
    }

    pub fn cancel_block_wait(
        &mut self,
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: &str,
    ) -> bool {
        if !matches!(
            reason,
            WaitCancelReason::DeviceFault
                | WaitCancelReason::CapabilityRevoked
                | WaitCancelReason::ResourceDropped
                | WaitCancelReason::GenerationMismatch
        ) {
            return false;
        }
        let Some(index) = self.domains.block.block_waits.iter().position(|record| {
            record.id == block_wait
                && record.generation == block_wait_generation
                && record.state == BlockWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.block.block_waits[index].clone();
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
            EventKind::BlockWaitCancelled {
                block_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                reason,
                generation: block_wait_generation,
            },
        );
        self.domains.block.block_waits[index].state = BlockWaitState::Cancelled;
        self.domains.block.block_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.block.block_waits[index].cancel_reason = Some(reason);
        self.domains.block.block_waits[index].note = note.to_string();
        true
    }

    pub fn block_waits(&self) -> &[BlockWaitRecord] {
        &self.domains.block.block_waits
    }

    pub fn block_wait_count(&self) -> usize {
        self.domains.block.block_waits.len()
    }

    pub fn check_block_wait_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.block.block_waits {
            let Some(wait_record) =
                self.domains.wait.waits.iter().find(|wait| {
                    wait.id == record.wait && wait.generation == record.wait_generation
                })
            else {
                return Err(SemanticInvariantError::BlockWaitMissingWait {
                    block_wait: record.id,
                    wait: record.wait,
                });
            };
            let Some(request) = self.domains.block.block_request_objects.iter().find(|request| {
                request.id == record.block_request
                    && request.generation == record.block_request_generation
            }) else {
                return Err(SemanticInvariantError::BlockWaitMissingRequest {
                    block_wait: record.id,
                    block_request: record.block_request,
                });
            };
            let expected_blocker = ContractObjectRef::new(
                ContractObjectKind::BlockRequestObject,
                record.block_request,
                record.block_request_generation,
            );
            if record.id == 0
                || record.generation == 0
                || record.wait_generation == 0
                || record.block_request_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.sequence == 0
                || record.byte_len == 0
                || wait_record.kind != SemanticWaitKind::DriverCompletion
                || !wait_record.blockers.contains(&expected_blocker)
                || request.block_device != record.block_device
                || request.block_device_generation != record.block_device_generation
                || request.block_range != record.block_range
                || request.block_range_generation != record.block_range_generation
                || request.operation != record.operation
                || request.sequence != record.sequence
                || request.byte_len != record.byte_len
            {
                return Err(SemanticInvariantError::BlockWaitInvalid { block_wait: record.id });
            }
            if record.state == BlockWaitState::Pending
                && self.domains.block.block_waits.iter().any(|other| {
                    other.id != record.id
                        && other.wait == record.wait
                        && other.wait_generation == record.wait_generation
                        && other.state == BlockWaitState::Pending
                })
            {
                return Err(SemanticInvariantError::BlockWaitDuplicateWait {
                    block_wait: record.id,
                    wait: record.wait,
                });
            }
            if record.state == BlockWaitState::Pending
                && self.domains.block.block_waits.iter().any(|other| {
                    other.id != record.id
                        && other.block_request == record.block_request
                        && other.block_request_generation == record.block_request_generation
                        && other.state == BlockWaitState::Pending
                })
            {
                return Err(SemanticInvariantError::BlockWaitInvalid { block_wait: record.id });
            }
            match record.state {
                BlockWaitState::Pending => {
                    if wait_record.state != WaitState::Pending
                        || request.state != BlockRequestObjectState::Submitted
                    {
                        return Err(SemanticInvariantError::BlockWaitInvalid {
                            block_wait: record.id,
                        });
                    }
                }
                BlockWaitState::Resolved => {
                    let Some(completion) = record.completion else {
                        return Err(SemanticInvariantError::BlockWaitInvalid {
                            block_wait: record.id,
                        });
                    };
                    let Some(completion_generation) = record.completion_generation else {
                        return Err(SemanticInvariantError::BlockWaitInvalid {
                            block_wait: record.id,
                        });
                    };
                    let Some(completion_record) =
                        self.domains.block.block_completion_objects.iter().find(
                            |completion_record| {
                                completion_record.id == completion
                                    && completion_record.generation == completion_generation
                            },
                        )
                    else {
                        return Err(SemanticInvariantError::BlockWaitMissingCompletion {
                            block_wait: record.id,
                            block_completion: completion,
                        });
                    };
                    if !matches!(wait_record.state, WaitState::Resolved | WaitState::Consumed)
                        || request.state != BlockRequestObjectState::Completed
                        || completion_record.block_request != record.block_request
                        || completion_record.block_request_generation
                            != record.block_request_generation
                        || completion_record.status != BlockCompletionStatus::Success
                        || completion_record.completed_bytes != record.byte_len
                    {
                        return Err(SemanticInvariantError::BlockWaitInvalid {
                            block_wait: record.id,
                        });
                    }
                }
                BlockWaitState::Cancelled => {
                    if wait_record.state != WaitState::Cancelled
                        || wait_record.cancel_reason != record.cancel_reason
                        || record.cancel_reason.is_none()
                    {
                        return Err(SemanticInvariantError::BlockWaitInvalid {
                            block_wait: record.id,
                        });
                    }
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockWaitCreated {
                            block_wait,
                            wait,
                            wait_generation,
                            block_request,
                            block_request_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            operation,
                            sequence,
                            byte_len,
                            generation,
                        } if *block_wait == record.id
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
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
                return Err(SemanticInvariantError::BlockWaitMissingEvent {
                    block_wait: record.id,
                    event: record.created_at_event,
                });
            }
            if let Some(completed_at_event) = record.completed_at_event {
                let found = self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && match (&record.state, &event.kind) {
                            (
                                BlockWaitState::Resolved,
                                EventKind::BlockWaitResolved {
                                    block_wait,
                                    wait,
                                    wait_generation,
                                    block_completion,
                                    block_completion_generation,
                                    generation,
                                },
                            ) => {
                                *block_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*block_completion) == record.completion
                                    && Some(*block_completion_generation)
                                        == record.completion_generation
                                    && *generation == record.generation
                            }
                            (
                                BlockWaitState::Cancelled,
                                EventKind::BlockWaitCancelled {
                                    block_wait,
                                    wait,
                                    wait_generation,
                                    reason,
                                    generation,
                                },
                            ) => {
                                *block_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*reason) == record.cancel_reason
                                    && *generation == record.generation
                            }
                            _ => false,
                        }
                });
                if !found {
                    return Err(SemanticInvariantError::BlockWaitMissingEvent {
                        block_wait: record.id,
                        event: completed_at_event,
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_wait_request_generation_for_test(
        &mut self,
        block_wait: BlockWaitId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.block.block_waits.iter_mut().find(|record| record.id == block_wait)
        {
            record.block_request_generation = generation;
        }
    }
}
