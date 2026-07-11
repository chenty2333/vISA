use super::*;

impl SemanticGraph {
    pub(super) fn preflight_block_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RecordBlockDeviceObject {
                block_device,
                name,
                device,
                device_generation,
                sector_size,
                sector_count,
                max_transfer_sectors,
                ..
            } => self
                .validate_block_device_object(
                    *block_device,
                    name,
                    *device,
                    *device_generation,
                    *sector_size,
                    *sector_count,
                    *max_transfer_sectors,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRangeObject {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                ..
            } => self
                .validate_block_range_object(
                    *block_range,
                    *block_device,
                    *block_device_generation,
                    *start_sector,
                    *sector_count,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestObject {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_block_request_object(
                    *block_request,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockCompletionObject {
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
                ..
            } => self
                .validate_block_completion_object(
                    *block_completion,
                    *block_request,
                    *block_request_generation,
                    *sequence,
                    *completed_bytes,
                    *status,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWait {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                ..
            } => self
                .validate_block_wait(
                    *block_wait,
                    *wait,
                    *wait_generation,
                    *block_request,
                    *block_request_generation,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveBlockWait {
                block_wait,
                block_wait_generation,
                block_completion,
                block_completion_generation,
                ..
            } => {
                let Some(record) = self.domains.block.block_waits.iter().find(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ));
                };
                let Some(completion) =
                    self.domains.block.block_completion_objects.iter().find(|completion| {
                        completion.id == *block_completion
                            && completion.generation == *block_completion_generation
                            && completion.state == BlockCompletionObjectState::Recorded
                    })
                else {
                    return Err(CommandError::precondition(
                        "block wait completion generation is missing",
                    ));
                };
                if completion.block_request == record.block_request
                    && completion.block_request_generation == record.block_request_generation
                    && completion.block_device == record.block_device
                    && completion.block_device_generation == record.block_device_generation
                    && completion.block_range == record.block_range
                    && completion.block_range_generation == record.block_range_generation
                    && completion.sequence == record.sequence
                    && completion.status == BlockCompletionStatus::Success
                    && completion.completed_bytes == record.byte_len
                    && self.domains.wait.waits.iter().any(|wait| {
                        wait.id == record.wait
                            && wait.generation == record.wait_generation
                            && wait.state == WaitState::Pending
                    })
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("block wait completion attribution mismatch"))
                }
            }
            SemanticCommand::CancelBlockWait {
                block_wait, block_wait_generation, reason, ..
            } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "block wait cancellation reason is not a block io reason",
                    ));
                }
                if self.domains.block.block_waits.iter().any(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
                ..
            } => self
                .validate_block_pending_io_policy(
                    *policy,
                    *block_wait,
                    *block_wait_generation,
                    *action,
                    *retry_request,
                    *retry_request_generation,
                    *errno,
                    *retry_attempt,
                    *max_retries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestGenerationAudit {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                ..
            } => self
                .validate_block_request_generation_audit(
                    *audit,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *block_request,
                    *block_request_generation,
                    *backend,
                    *dma_buffer,
                    *rejected_completion_generation_probes,
                    *rejected_wait_generation_probes,
                    *rejected_dma_generation_probes,
                    *rejected_queue_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockBenchmark {
                benchmark,
                scenario,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_block_benchmark(
                    *benchmark,
                    scenario,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *read_path,
                    *read_path_generation,
                    *write_path,
                    *write_path_generation,
                    *request_queue,
                    *request_queue_generation,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *sample_requests,
                    *sample_bytes,
                    *read_completed_requests,
                    *write_completed_requests,
                    *queue_completed_requests,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_block_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_block_waits,
                    *cancelled_wait_tokens,
                    *released_dma_buffers,
                    *revoked_device_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
