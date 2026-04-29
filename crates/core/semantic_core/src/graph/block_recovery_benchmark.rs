use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_recovery_benchmark(
        &self,
        benchmark: BlockRecoveryBenchmarkId,
        scenario: &str,
        cleanup: BlockDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_block_waits: u32,
        cancelled_wait_tokens: u32,
        released_dma_buffers: u32,
        revoked_device_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("block recovery benchmark id=0 is invalid");
        }
        if benchmark == u64::MAX {
            return Err("block recovery benchmark id cannot advance generation cursor");
        }
        if self.block_recovery_benchmarks.iter().any(|record| record.id == benchmark) {
            return Err("block recovery benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("block recovery benchmark scenario is empty");
        }
        if recovery_start_event == 0 || recovery_complete_event == 0 {
            return Err("block recovery benchmark event ids are invalid");
        }
        if recovery_start_event >= recovery_complete_event {
            return Err("block recovery benchmark event order is invalid");
        }
        if recovery_nanos == 0 || budget_nanos == 0 {
            return Err("block recovery benchmark timing is empty");
        }
        if recovery_nanos > budget_nanos {
            return Err("block recovery benchmark exceeds recovery budget");
        }
        if cancelled_block_waits == 0
            && cancelled_wait_tokens == 0
            && released_dma_buffers == 0
            && revoked_device_capabilities == 0
        {
            return Err("block recovery benchmark requires cleanup effects");
        }

        let Some(cleanup_record) = self.block_driver_cleanups.iter().find(|record| {
            record.id == cleanup
                && record.generation == cleanup_generation
                && record.state == BlockDriverCleanupState::Completed
        }) else {
            return Err("block recovery benchmark cleanup generation is missing or incomplete");
        };
        let Some(completed_at_event) = cleanup_record.completed_at_event else {
            return Err("block recovery benchmark cleanup completion event is missing");
        };
        if cleanup_record.io_cleanup != io_cleanup
            || cleanup_record.io_cleanup_generation != io_cleanup_generation
            || cleanup_record.started_at_event != recovery_start_event
            || completed_at_event != recovery_complete_event
        {
            return Err("block recovery benchmark cleanup references do not match");
        }
        if cleanup_record.cancelled_block_waits.len() > u32::MAX as usize
            || cleanup_record.cancelled_wait_tokens.len() > u32::MAX as usize
            || cleanup_record.released_dma_buffers.len() > u32::MAX as usize
            || cleanup_record.revoked_device_capabilities.len() > u32::MAX as usize
            || cleanup_record.cancelled_block_waits.len() as u32 != cancelled_block_waits
            || cleanup_record.cancelled_wait_tokens.len() as u32 != cancelled_wait_tokens
            || cleanup_record.released_dma_buffers.len() as u32 != released_dma_buffers
            || cleanup_record.revoked_device_capabilities.len() as u32
                != revoked_device_capabilities
        {
            return Err("block recovery benchmark cleanup effect counts do not match");
        }

        if self.check_invariants().is_err() {
            return Err("block recovery benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_recovery_benchmark_with_id(
        &mut self,
        benchmark: BlockRecoveryBenchmarkId,
        scenario: &str,
        cleanup: BlockDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_block_waits: u32,
        cancelled_wait_tokens: u32,
        released_dma_buffers: u32,
        revoked_device_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_block_recovery_benchmark(
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
            )
            .is_err()
        {
            return false;
        }

        let Some(cleanup_record) = self
            .block_driver_cleanups
            .iter()
            .find(|record| record.id == cleanup && record.generation == cleanup_generation)
        else {
            return false;
        };
        let backend = cleanup_record.backend;
        let block_device = cleanup_record.block_device;
        let block_device_generation = cleanup_record.block_device_generation;
        let driver_store = cleanup_record.driver_store;
        let driver_store_generation = cleanup_record.driver_store_generation;
        let device = cleanup_record.device;
        let device_generation = cleanup_record.device_generation;
        let driver_binding = cleanup_record.driver_binding;
        let driver_binding_generation = cleanup_record.driver_binding_generation;
        let generation = 1;
        self.next_block_recovery_benchmark_id =
            self.next_block_recovery_benchmark_id.max(benchmark.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockRecoveryBenchmarkRecorded {
                benchmark,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                backend,
                block_device,
                block_device_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                generation,
            },
        );
        self.block_recovery_benchmarks.push(BlockRecoveryBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
            cleanup,
            cleanup_generation,
            io_cleanup,
            io_cleanup_generation,
            backend,
            block_device,
            block_device_generation,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            recovery_start_event,
            recovery_complete_event,
            cancelled_block_waits,
            cancelled_wait_tokens,
            released_dma_buffers,
            revoked_device_capabilities,
            recovery_nanos,
            budget_nanos,
            generation,
            state: BlockRecoveryBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_recovery_benchmarks(&self) -> &[BlockRecoveryBenchmarkRecord] {
        &self.block_recovery_benchmarks
    }

    pub fn block_recovery_benchmark_count(&self) -> usize {
        self.block_recovery_benchmarks.len()
    }

    pub fn check_block_recovery_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_recovery_benchmarks {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.cleanup_generation == 0
                || record.io_cleanup_generation == 0
                || record.backend.kind != ContractObjectKind::VirtioBlkBackendObject
                || record.block_device_generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.driver_binding_generation == 0
                || record.recovery_start_event == 0
                || record.recovery_complete_event == 0
                || record.recovery_start_event >= record.recovery_complete_event
                || record.cancelled_block_waits == 0
                    && record.cancelled_wait_tokens == 0
                    && record.released_dma_buffers == 0
                    && record.revoked_device_capabilities == 0
                || record.recovery_nanos == 0
                || record.budget_nanos == 0
                || record.recovery_nanos > record.budget_nanos
                || record.state != BlockRecoveryBenchmarkState::Recorded
            {
                return Err(SemanticInvariantError::BlockRecoveryBenchmarkInvalid {
                    benchmark: record.id,
                });
            }

            let Some(cleanup) = self.block_driver_cleanups.iter().find(|cleanup| {
                cleanup.id == record.cleanup
                    && cleanup.generation == record.cleanup_generation
                    && cleanup.state == BlockDriverCleanupState::Completed
            }) else {
                return Err(SemanticInvariantError::BlockRecoveryBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockDriverCleanup,
                        record.cleanup,
                        record.cleanup_generation,
                    ),
                });
            };
            let Some(completed_at_event) = cleanup.completed_at_event else {
                return Err(SemanticInvariantError::BlockRecoveryBenchmarkInvalid {
                    benchmark: record.id,
                });
            };
            if cleanup.io_cleanup != record.io_cleanup
                || cleanup.io_cleanup_generation != record.io_cleanup_generation
                || cleanup.backend != record.backend
                || cleanup.block_device != record.block_device
                || cleanup.block_device_generation != record.block_device_generation
                || cleanup.driver_store != record.driver_store
                || cleanup.driver_store_generation != record.driver_store_generation
                || cleanup.device != record.device
                || cleanup.device_generation != record.device_generation
                || cleanup.driver_binding != record.driver_binding
                || cleanup.driver_binding_generation != record.driver_binding_generation
                || cleanup.started_at_event != record.recovery_start_event
                || completed_at_event != record.recovery_complete_event
                || cleanup.cancelled_block_waits.len() > u32::MAX as usize
                || cleanup.cancelled_wait_tokens.len() > u32::MAX as usize
                || cleanup.released_dma_buffers.len() > u32::MAX as usize
                || cleanup.revoked_device_capabilities.len() > u32::MAX as usize
                || cleanup.cancelled_block_waits.len() as u32 != record.cancelled_block_waits
                || cleanup.cancelled_wait_tokens.len() as u32 != record.cancelled_wait_tokens
                || cleanup.released_dma_buffers.len() as u32 != record.released_dma_buffers
                || cleanup.revoked_device_capabilities.len() as u32
                    != record.revoked_device_capabilities
            {
                return Err(SemanticInvariantError::BlockRecoveryBenchmarkMetricMismatch {
                    benchmark: record.id,
                });
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockRecoveryBenchmarkRecorded {
                            benchmark,
                            cleanup,
                            cleanup_generation,
                            io_cleanup,
                            io_cleanup_generation,
                            backend,
                            block_device,
                            block_device_generation,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            recovery_start_event,
                            recovery_complete_event,
                            cancelled_block_waits,
                            cancelled_wait_tokens,
                            released_dma_buffers,
                            revoked_device_capabilities,
                            recovery_nanos,
                            budget_nanos,
                            generation,
                        } if *benchmark == record.id
                            && *cleanup == record.cleanup
                            && *cleanup_generation == record.cleanup_generation
                            && *io_cleanup == record.io_cleanup
                            && *io_cleanup_generation == record.io_cleanup_generation
                            && *backend == record.backend
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *driver_binding == record.driver_binding
                            && *driver_binding_generation == record.driver_binding_generation
                            && *recovery_start_event == record.recovery_start_event
                            && *recovery_complete_event == record.recovery_complete_event
                            && *cancelled_block_waits == record.cancelled_block_waits
                            && *cancelled_wait_tokens == record.cancelled_wait_tokens
                            && *released_dma_buffers == record.released_dma_buffers
                            && *revoked_device_capabilities == record.revoked_device_capabilities
                            && *recovery_nanos == record.recovery_nanos
                            && *budget_nanos == record.budget_nanos
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockRecoveryBenchmarkMissingEvent {
                    benchmark: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_recovery_benchmark_cleanup_generation_for_test(
        &mut self,
        benchmark: BlockRecoveryBenchmarkId,
        cleanup_generation: Generation,
    ) {
        if let Some(record) =
            self.block_recovery_benchmarks.iter_mut().find(|record| record.id == benchmark)
        {
            record.cleanup_generation = cleanup_generation;
        }
    }
}
