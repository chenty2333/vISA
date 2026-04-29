use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_pending_io_policy(
        &self,
        policy: BlockPendingIoPolicyId,
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        action: BlockPendingIoAction,
        retry_request: Option<BlockRequestObjectId>,
        retry_request_generation: Option<Generation>,
        errno: i32,
        retry_attempt: u32,
        max_retries: u32,
    ) -> Result<&BlockWaitRecord, &'static str> {
        if policy == 0 {
            return Err("block pending io policy id=0 is invalid");
        }
        if block_wait_generation == 0 {
            return Err("block pending io policy block wait generation is invalid");
        }
        if errno <= 0 {
            return Err("block pending io policy errno must be positive");
        }
        if self.block_pending_io_policies.iter().any(|record| record.id == policy) {
            return Err("block pending io policy already exists");
        }
        if self.block_pending_io_policies.iter().any(|record| {
            record.block_wait == block_wait && record.block_wait_generation == block_wait_generation
        }) {
            return Err("block wait already has a pending io policy");
        }
        let Some(wait_record) = self.block_waits.iter().find(|record| {
            record.id == block_wait
                && record.generation == block_wait_generation
                && record.state == BlockWaitState::Pending
        }) else {
            return Err("block wait generation is missing or not pending");
        };
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == wait_record.wait
                && wait.generation == wait_record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return Err("block pending io wait token is missing or not pending");
        }
        let Some(request_record) = self.block_request_objects.iter().find(|request| {
            request.id == wait_record.block_request
                && request.generation == wait_record.block_request_generation
                && request.state == BlockRequestObjectState::Submitted
        }) else {
            return Err("block pending io request generation is missing or not submitted");
        };
        match action {
            BlockPendingIoAction::Cancel => {
                if retry_request.is_some() || retry_request_generation.is_some() {
                    return Err("cancel policy must not carry retry request");
                }
            }
            BlockPendingIoAction::Eio => {
                if retry_request.is_some() || retry_request_generation.is_some() {
                    return Err("eio policy must not carry retry request");
                }
                if errno != 5 {
                    return Err("eio policy must return errno 5");
                }
            }
            BlockPendingIoAction::Retry => {
                if retry_attempt == 0 || max_retries == 0 || retry_attempt > max_retries {
                    return Err("retry policy retry attempt is outside max retries");
                }
                let Some(retry_request) = retry_request else {
                    return Err("retry policy missing retry request");
                };
                let Some(retry_generation) = retry_request_generation else {
                    return Err("retry policy missing retry request generation");
                };
                let Some(retry_record) = self.block_request_objects.iter().find(|request| {
                    request.id == retry_request
                        && request.generation == retry_generation
                        && request.state == BlockRequestObjectState::Submitted
                }) else {
                    return Err(
                        "retry policy retry request generation is missing or not submitted",
                    );
                };
                if (retry_record.id == request_record.id
                    && retry_record.generation == request_record.generation)
                    || retry_record.block_device != request_record.block_device
                    || retry_record.block_device_generation
                        != request_record.block_device_generation
                    || retry_record.block_range != request_record.block_range
                    || retry_record.block_range_generation != request_record.block_range_generation
                    || retry_record.operation != request_record.operation
                    || retry_record.byte_len != request_record.byte_len
                    || retry_record.sequence <= request_record.sequence
                {
                    return Err("retry policy retry request attribution mismatch");
                }
            }
        }
        if self.check_invariants().is_err() {
            return Err("block pending io policy requires invariant-clean graph");
        }
        Ok(wait_record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_block_pending_io_policy_with_id(
        &mut self,
        policy: BlockPendingIoPolicyId,
        block_wait: BlockWaitId,
        block_wait_generation: Generation,
        action: BlockPendingIoAction,
        retry_request: Option<BlockRequestObjectId>,
        retry_request_generation: Option<Generation>,
        errno: i32,
        retry_attempt: u32,
        max_retries: u32,
        note: &str,
    ) -> bool {
        let Ok(wait_snapshot) = self
            .validate_block_pending_io_policy(
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
            )
            .cloned()
        else {
            return false;
        };

        let cancel_reason = match action {
            BlockPendingIoAction::Cancel => WaitCancelReason::ResourceDropped,
            BlockPendingIoAction::Retry | BlockPendingIoAction::Eio => {
                WaitCancelReason::DeviceFault
            }
        };
        if !self.cancel_block_wait(block_wait, block_wait_generation, errno, cancel_reason, note) {
            return false;
        }

        let generation = 1;
        self.next_block_pending_io_policy_id =
            self.next_block_pending_io_policy_id.max(policy.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockPendingIoPolicyApplied {
                policy,
                block_wait,
                block_wait_generation,
                wait: wait_snapshot.wait,
                wait_generation: wait_snapshot.wait_generation,
                block_request: wait_snapshot.block_request,
                block_request_generation: wait_snapshot.block_request_generation,
                retry_request,
                retry_request_generation,
                block_device: wait_snapshot.block_device,
                block_device_generation: wait_snapshot.block_device_generation,
                block_range: wait_snapshot.block_range,
                block_range_generation: wait_snapshot.block_range_generation,
                action,
                errno,
                retry_attempt,
                max_retries,
                generation,
            },
        );
        let state = match action {
            BlockPendingIoAction::Cancel => BlockPendingIoPolicyState::Cancelled,
            BlockPendingIoAction::Retry => BlockPendingIoPolicyState::RetryScheduled,
            BlockPendingIoAction::Eio => BlockPendingIoPolicyState::EioReturned,
        };
        self.block_pending_io_policies.push(BlockPendingIoPolicyRecord {
            id: policy,
            block_wait,
            block_wait_generation,
            wait: wait_snapshot.wait,
            wait_generation: wait_snapshot.wait_generation,
            block_request: wait_snapshot.block_request,
            block_request_generation: wait_snapshot.block_request_generation,
            retry_request,
            retry_request_generation,
            block_device: wait_snapshot.block_device,
            block_device_generation: wait_snapshot.block_device_generation,
            block_range: wait_snapshot.block_range,
            block_range_generation: wait_snapshot.block_range_generation,
            operation: wait_snapshot.operation,
            sequence: wait_snapshot.sequence,
            byte_len: wait_snapshot.byte_len,
            action,
            errno,
            retry_attempt,
            max_retries,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        self.check_invariants().is_ok()
    }

    pub fn block_pending_io_policies(&self) -> &[BlockPendingIoPolicyRecord] {
        &self.block_pending_io_policies
    }

    pub fn block_pending_io_policy_count(&self) -> usize {
        self.block_pending_io_policies.len()
    }

    pub fn check_block_pending_io_policy_invariants(&self) -> Result<(), SemanticInvariantError> {
        for policy in &self.block_pending_io_policies {
            if policy.id == 0
                || policy.generation == 0
                || policy.block_wait_generation == 0
                || policy.wait_generation == 0
                || policy.block_request_generation == 0
                || policy.block_device_generation == 0
                || policy.block_range_generation == 0
                || policy.sequence == 0
                || policy.byte_len == 0
                || policy.errno <= 0
            {
                return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                    policy: policy.id,
                });
            }
            let Some(block_wait) = self.block_waits.iter().find(|record| {
                record.id == policy.block_wait && record.generation == policy.block_wait_generation
            }) else {
                return Err(SemanticInvariantError::BlockPendingIoPolicyMissingBlockWait {
                    policy: policy.id,
                    block_wait: policy.block_wait,
                });
            };
            let Some(request) = self.block_request_objects.iter().find(|record| {
                record.id == policy.block_request
                    && record.generation == policy.block_request_generation
            }) else {
                return Err(SemanticInvariantError::BlockPendingIoPolicyMissingRequest {
                    policy: policy.id,
                    block_request: policy.block_request,
                });
            };
            if block_wait.state != BlockWaitState::Cancelled
                || block_wait.wait != policy.wait
                || block_wait.wait_generation != policy.wait_generation
                || block_wait.block_request != policy.block_request
                || block_wait.block_request_generation != policy.block_request_generation
                || block_wait.block_device != policy.block_device
                || block_wait.block_device_generation != policy.block_device_generation
                || block_wait.block_range != policy.block_range
                || block_wait.block_range_generation != policy.block_range_generation
                || block_wait.operation != policy.operation
                || block_wait.sequence != policy.sequence
                || block_wait.byte_len != policy.byte_len
                || request.block_device != policy.block_device
                || request.block_device_generation != policy.block_device_generation
                || request.block_range != policy.block_range
                || request.block_range_generation != policy.block_range_generation
                || request.operation != policy.operation
                || request.sequence != policy.sequence
                || request.byte_len != policy.byte_len
            {
                return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                    policy: policy.id,
                });
            }
            let expected_reason = match policy.action {
                BlockPendingIoAction::Cancel => WaitCancelReason::ResourceDropped,
                BlockPendingIoAction::Retry | BlockPendingIoAction::Eio => {
                    WaitCancelReason::DeviceFault
                }
            };
            if block_wait.cancel_reason != Some(expected_reason) {
                return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                    policy: policy.id,
                });
            }
            match policy.action {
                BlockPendingIoAction::Cancel => {
                    if policy.state != BlockPendingIoPolicyState::Cancelled
                        || policy.retry_request.is_some()
                        || policy.retry_request_generation.is_some()
                    {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    }
                }
                BlockPendingIoAction::Eio => {
                    if policy.state != BlockPendingIoPolicyState::EioReturned
                        || policy.errno != 5
                        || policy.retry_request.is_some()
                        || policy.retry_request_generation.is_some()
                    {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    }
                }
                BlockPendingIoAction::Retry => {
                    if policy.state != BlockPendingIoPolicyState::RetryScheduled
                        || policy.retry_attempt == 0
                        || policy.max_retries == 0
                        || policy.retry_attempt > policy.max_retries
                    {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    }
                    let Some(retry_request) = policy.retry_request else {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    };
                    let Some(retry_generation) = policy.retry_request_generation else {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    };
                    let Some(retry_record) = self.block_request_objects.iter().find(|record| {
                        record.id == retry_request && record.generation == retry_generation
                    }) else {
                        return Err(
                            SemanticInvariantError::BlockPendingIoPolicyMissingRetryRequest {
                                policy: policy.id,
                                block_request: retry_request,
                            },
                        );
                    };
                    if (retry_record.id == policy.block_request
                        && retry_record.generation == policy.block_request_generation)
                        || retry_record.block_device != policy.block_device
                        || retry_record.block_device_generation != policy.block_device_generation
                        || retry_record.block_range != policy.block_range
                        || retry_record.block_range_generation != policy.block_range_generation
                        || retry_record.operation != policy.operation
                        || retry_record.byte_len != policy.byte_len
                        || retry_record.sequence <= policy.sequence
                    {
                        return Err(SemanticInvariantError::BlockPendingIoPolicyInvalid {
                            policy: policy.id,
                        });
                    }
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == policy.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockPendingIoPolicyApplied {
                            policy: id,
                            block_wait,
                            block_wait_generation,
                            wait,
                            wait_generation,
                            block_request,
                            block_request_generation,
                            retry_request,
                            retry_request_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            action,
                            errno,
                            retry_attempt,
                            max_retries,
                            generation,
                        } if *id == policy.id
                            && *block_wait == policy.block_wait
                            && *block_wait_generation == policy.block_wait_generation
                            && *wait == policy.wait
                            && *wait_generation == policy.wait_generation
                            && *block_request == policy.block_request
                            && *block_request_generation == policy.block_request_generation
                            && *retry_request == policy.retry_request
                            && *retry_request_generation == policy.retry_request_generation
                            && *block_device == policy.block_device
                            && *block_device_generation == policy.block_device_generation
                            && *block_range == policy.block_range
                            && *block_range_generation == policy.block_range_generation
                            && *action == policy.action
                            && *errno == policy.errno
                            && *retry_attempt == policy.retry_attempt
                            && *max_retries == policy.max_retries
                            && *generation == policy.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockPendingIoPolicyMissingEvent {
                    policy: policy.id,
                    event: policy.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_pending_io_policy_retry_generation_for_test(
        &mut self,
        policy: BlockPendingIoPolicyId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.block_pending_io_policies.iter_mut().find(|record| record.id == policy)
        {
            record.retry_request_generation = Some(generation);
        }
    }
}
