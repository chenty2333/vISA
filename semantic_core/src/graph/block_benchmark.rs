use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_benchmark(
        &self,
        benchmark: BlockBenchmarkId,
        scenario: &str,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        read_path: BlockReadPathId,
        read_path_generation: Generation,
        write_path: BlockWritePathId,
        write_path_generation: Generation,
        request_queue: BlockRequestQueueId,
        request_queue_generation: Generation,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        sample_requests: u32,
        sample_bytes: u64,
        read_completed_requests: u32,
        write_completed_requests: u32,
        queue_completed_requests: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("block benchmark id=0 is invalid");
        }
        if benchmark == u64::MAX {
            return Err("block benchmark id cannot advance generation cursor");
        }
        if self
            .block_benchmarks
            .iter()
            .any(|record| record.id == benchmark)
        {
            return Err("block benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("block benchmark scenario is empty");
        }
        if backend.generation == 0
            || block_device_generation == 0
            || block_range_generation == 0
            || read_path_generation == 0
            || write_path_generation == 0
            || request_queue_generation == 0
            || block_dma_buffer_generation == 0
        {
            return Err("block benchmark identity values must be nonzero");
        }
        if backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("block benchmark backend kind is unsupported for B22");
        }
        if sample_requests == 0
            || sample_bytes == 0
            || read_completed_requests == 0
            || write_completed_requests == 0
            || queue_completed_requests == 0
            || measured_nanos == 0
            || budget_nanos == 0
            || p50_latency_nanos == 0
            || p99_latency_nanos == 0
        {
            return Err("block benchmark metrics require nonzero samples and timing");
        }
        if measured_nanos > budget_nanos {
            return Err("block benchmark exceeds latency budget");
        }
        if p99_latency_nanos < p50_latency_nanos || p99_latency_nanos > measured_nanos {
            return Err("block benchmark latency distribution is invalid");
        }
        let Some(accounted_requests) =
            read_completed_requests.checked_add(write_completed_requests)
        else {
            return Err("block benchmark request accounting overflow");
        };
        if accounted_requests != sample_requests || queue_completed_requests != sample_requests {
            return Err("block benchmark request accounting is not closed");
        }
        if Self::derive_block_iops(sample_requests, measured_nanos).is_none()
            || Self::derive_block_throughput_bytes_per_sec(sample_bytes, measured_nanos).is_none()
        {
            return Err("block benchmark metric overflow");
        }

        let Some(backend_record) = self.fake_block_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) else {
            return Err("block benchmark backend generation is missing or inactive");
        };
        if backend_record.block_device != block_device
            || backend_record.block_device_generation != block_device_generation
        {
            return Err("block benchmark backend does not match block device");
        }

        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err("block benchmark block device generation is missing or inactive");
        };
        let Some(block_range_record) = self.block_range_objects.iter().find(|record| {
            record.id == block_range
                && record.generation == block_range_generation
                && record.state == BlockRangeObjectState::Registered
        }) else {
            return Err("block benchmark block range generation is missing or inactive");
        };
        if block_range_record.block_device != block_device_record.id
            || block_range_record.block_device_generation != block_device_record.generation
        {
            return Err("block benchmark range does not match block device");
        }

        let Some(read_record) = self.block_read_paths.iter().find(|record| {
            record.id == read_path
                && record.generation == read_path_generation
                && record.state == BlockReadPathState::Completed
        }) else {
            return Err("block benchmark read path generation is missing or inactive");
        };
        let Some(write_record) = self.block_write_paths.iter().find(|record| {
            record.id == write_path
                && record.generation == write_path_generation
                && record.state == BlockWritePathState::Completed
        }) else {
            return Err("block benchmark write path generation is missing or inactive");
        };
        if read_record.backend != backend
            || write_record.backend != backend
            || read_record.block_device != block_device
            || read_record.block_device_generation != block_device_generation
            || write_record.block_device != block_device
            || write_record.block_device_generation != block_device_generation
            || read_record.block_range != block_range
            || read_record.block_range_generation != block_range_generation
            || write_record.block_range != block_range
            || write_record.block_range_generation != block_range_generation
        {
            return Err("block benchmark read/write path references do not match");
        }
        if sample_bytes
            != read_record
                .completed_bytes
                .checked_add(write_record.completed_bytes)
                .ok_or("block benchmark byte accounting overflow")?
        {
            return Err("block benchmark byte accounting is not closed");
        }

        let Some(queue_record) = self.block_request_queues.iter().find(|record| {
            record.id == request_queue
                && record.generation == request_queue_generation
                && record.state == BlockRequestQueueState::Active
        }) else {
            return Err("block benchmark request queue generation is missing or inactive");
        };
        if queue_record.backend != backend
            || queue_record.block_device != block_device
            || queue_record.block_device_generation != block_device_generation
            || queue_record.completed_count != queue_completed_requests
            || queue_record.pending_count != 0
        {
            return Err("block benchmark queue evidence does not match");
        }
        let read_queued = queue_record.entries.iter().any(|entry| {
            entry.request == read_record.block_request
                && entry.request_generation == read_record.block_request_generation
                && entry.completion == Some(read_record.block_completion)
                && entry.completion_generation == Some(read_record.block_completion_generation)
                && entry.state == BlockRequestQueueEntryState::Completed
        });
        let write_queued = queue_record.entries.iter().any(|entry| {
            entry.request == write_record.block_request
                && entry.request_generation == write_record.block_request_generation
                && entry.completion == Some(write_record.block_completion)
                && entry.completion_generation == Some(write_record.block_completion_generation)
                && entry.state == BlockRequestQueueEntryState::Completed
        });
        if !read_queued || !write_queued {
            return Err("block benchmark queue is missing read/write completions");
        }

        let Some(dma_record) = self.block_dma_buffers.iter().find(|record| {
            record.id == block_dma_buffer
                && record.generation == block_dma_buffer_generation
                && record.state == BlockDmaBufferState::Bound
        }) else {
            return Err("block benchmark dma buffer generation is missing or inactive");
        };
        if dma_record.backend != backend
            || dma_record.block_request != write_record.block_request
            || dma_record.block_request_generation != write_record.block_request_generation
            || dma_record.block_device != block_device
            || dma_record.block_device_generation != block_device_generation
            || dma_record.block_range != block_range
            || dma_record.block_range_generation != block_range_generation
            || dma_record.byte_len != write_record.completed_bytes
        {
            return Err("block benchmark dma evidence does not match write path");
        }

        if self.check_invariants().is_err() {
            return Err("block benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_benchmark_with_id(
        &mut self,
        benchmark: BlockBenchmarkId,
        scenario: &str,
        backend: ContractObjectRef,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        read_path: BlockReadPathId,
        read_path_generation: Generation,
        write_path: BlockWritePathId,
        write_path_generation: Generation,
        request_queue: BlockRequestQueueId,
        request_queue_generation: Generation,
        block_dma_buffer: BlockDmaBufferId,
        block_dma_buffer_generation: Generation,
        sample_requests: u32,
        sample_bytes: u64,
        read_completed_requests: u32,
        write_completed_requests: u32,
        queue_completed_requests: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_block_benchmark(
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
            )
            .is_err()
        {
            return false;
        }
        let Some(iops) = Self::derive_block_iops(sample_requests, measured_nanos) else {
            return false;
        };
        let Some(throughput_bytes_per_sec) =
            Self::derive_block_throughput_bytes_per_sec(sample_bytes, measured_nanos)
        else {
            return false;
        };
        let generation = 1;
        self.next_block_benchmark_id = self
            .next_block_benchmark_id
            .max(benchmark.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockBenchmarkRecorded {
                benchmark,
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
                iops,
                throughput_bytes_per_sec,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            },
        );
        self.block_benchmarks.push(BlockBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
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
            iops,
            throughput_bytes_per_sec,
            p50_latency_nanos,
            p99_latency_nanos,
            generation,
            state: BlockBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_benchmarks(&self) -> &[BlockBenchmarkRecord] {
        &self.block_benchmarks
    }

    pub fn block_benchmark_count(&self) -> usize {
        self.block_benchmarks.len()
    }

    pub fn derive_block_iops(sample_requests: u32, measured_nanos: u64) -> Option<u64> {
        u64::from(sample_requests)
            .checked_mul(1_000_000_000)?
            .checked_div(measured_nanos)
    }

    pub fn derive_block_throughput_bytes_per_sec(
        sample_bytes: u64,
        measured_nanos: u64,
    ) -> Option<u64> {
        sample_bytes
            .checked_mul(1_000_000_000)?
            .checked_div(measured_nanos)
    }

    pub fn check_block_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for benchmark in &self.block_benchmarks {
            let expected_iops =
                Self::derive_block_iops(benchmark.sample_requests, benchmark.measured_nanos);
            let expected_throughput = Self::derive_block_throughput_bytes_per_sec(
                benchmark.sample_bytes,
                benchmark.measured_nanos,
            );
            let accounted_requests = benchmark
                .read_completed_requests
                .checked_add(benchmark.write_completed_requests);
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.scenario.is_empty()
                || benchmark.backend.generation == 0
                || benchmark.block_device_generation == 0
                || benchmark.block_range_generation == 0
                || benchmark.read_path_generation == 0
                || benchmark.write_path_generation == 0
                || benchmark.request_queue_generation == 0
                || benchmark.block_dma_buffer_generation == 0
                || benchmark.sample_requests == 0
                || benchmark.sample_bytes == 0
                || benchmark.read_completed_requests == 0
                || benchmark.write_completed_requests == 0
                || benchmark.queue_completed_requests != benchmark.sample_requests
                || accounted_requests != Some(benchmark.sample_requests)
                || benchmark.measured_nanos == 0
                || benchmark.budget_nanos == 0
                || benchmark.measured_nanos > benchmark.budget_nanos
                || benchmark.iops == 0
                || benchmark.throughput_bytes_per_sec == 0
                || expected_iops != Some(benchmark.iops)
                || expected_throughput != Some(benchmark.throughput_bytes_per_sec)
                || benchmark.p50_latency_nanos == 0
                || benchmark.p99_latency_nanos < benchmark.p50_latency_nanos
                || benchmark.p99_latency_nanos > benchmark.measured_nanos
                || benchmark.state != BlockBenchmarkState::Recorded
            {
                return Err(SemanticInvariantError::BlockBenchmarkInvalid {
                    benchmark: benchmark.id,
                });
            }

            let Some(backend) = self.fake_block_backends.iter().find(|record| {
                benchmark.backend.kind == ContractObjectKind::FakeBlockBackendObject
                    && record.id == benchmark.backend.id
                    && record.generation == benchmark.backend.generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: benchmark.backend,
                });
            };
            let Some(block_device) = self.block_device_objects.iter().find(|record| {
                record.id == benchmark.block_device
                    && record.generation == benchmark.block_device_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockDeviceObject,
                        benchmark.block_device,
                        benchmark.block_device_generation,
                    ),
                });
            };
            let Some(block_range) = self.block_range_objects.iter().find(|record| {
                record.id == benchmark.block_range
                    && record.generation == benchmark.block_range_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockRangeObject,
                        benchmark.block_range,
                        benchmark.block_range_generation,
                    ),
                });
            };
            if backend.state != FakeBlockBackendObjectState::Bound
                || block_device.state != BlockDeviceObjectState::Registered
                || block_range.state != BlockRangeObjectState::Registered
                || backend.block_device != benchmark.block_device
                || backend.block_device_generation != benchmark.block_device_generation
                || block_range.block_device != benchmark.block_device
                || block_range.block_device_generation != benchmark.block_device_generation
            {
                return Err(SemanticInvariantError::BlockBenchmarkInvalid {
                    benchmark: benchmark.id,
                });
            }

            let Some(read_path) = self.block_read_paths.iter().find(|record| {
                record.id == benchmark.read_path
                    && record.generation == benchmark.read_path_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockReadPath,
                        benchmark.read_path,
                        benchmark.read_path_generation,
                    ),
                });
            };
            let Some(write_path) = self.block_write_paths.iter().find(|record| {
                record.id == benchmark.write_path
                    && record.generation == benchmark.write_path_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockWritePath,
                        benchmark.write_path,
                        benchmark.write_path_generation,
                    ),
                });
            };
            if read_path.state != BlockReadPathState::Completed
                || write_path.state != BlockWritePathState::Completed
                || read_path.backend != benchmark.backend
                || write_path.backend != benchmark.backend
                || read_path.block_device != benchmark.block_device
                || read_path.block_device_generation != benchmark.block_device_generation
                || write_path.block_device != benchmark.block_device
                || write_path.block_device_generation != benchmark.block_device_generation
                || read_path.block_range != benchmark.block_range
                || read_path.block_range_generation != benchmark.block_range_generation
                || write_path.block_range != benchmark.block_range
                || write_path.block_range_generation != benchmark.block_range_generation
                || benchmark.sample_bytes
                    != read_path
                        .completed_bytes
                        .checked_add(write_path.completed_bytes)
                        .unwrap_or(0)
            {
                return Err(SemanticInvariantError::BlockBenchmarkMetricMismatch {
                    benchmark: benchmark.id,
                });
            }

            let Some(queue) = self.block_request_queues.iter().find(|record| {
                record.id == benchmark.request_queue
                    && record.generation == benchmark.request_queue_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockRequestQueue,
                        benchmark.request_queue,
                        benchmark.request_queue_generation,
                    ),
                });
            };
            let read_queued = queue.entries.iter().any(|entry| {
                entry.request == read_path.block_request
                    && entry.request_generation == read_path.block_request_generation
                    && entry.completion == Some(read_path.block_completion)
                    && entry.completion_generation == Some(read_path.block_completion_generation)
                    && entry.state == BlockRequestQueueEntryState::Completed
            });
            let write_queued = queue.entries.iter().any(|entry| {
                entry.request == write_path.block_request
                    && entry.request_generation == write_path.block_request_generation
                    && entry.completion == Some(write_path.block_completion)
                    && entry.completion_generation == Some(write_path.block_completion_generation)
                    && entry.state == BlockRequestQueueEntryState::Completed
            });
            if queue.state != BlockRequestQueueState::Active
                || queue.backend != benchmark.backend
                || queue.block_device != benchmark.block_device
                || queue.block_device_generation != benchmark.block_device_generation
                || queue.pending_count != 0
                || queue.completed_count != benchmark.queue_completed_requests
                || !read_queued
                || !write_queued
            {
                return Err(SemanticInvariantError::BlockBenchmarkMetricMismatch {
                    benchmark: benchmark.id,
                });
            }

            let Some(dma) = self.block_dma_buffers.iter().find(|record| {
                record.id == benchmark.block_dma_buffer
                    && record.generation == benchmark.block_dma_buffer_generation
            }) else {
                return Err(SemanticInvariantError::BlockBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::BlockDmaBuffer,
                        benchmark.block_dma_buffer,
                        benchmark.block_dma_buffer_generation,
                    ),
                });
            };
            if dma.state != BlockDmaBufferState::Bound
                || dma.backend != benchmark.backend
                || dma.block_request != write_path.block_request
                || dma.block_request_generation != write_path.block_request_generation
                || dma.block_device != benchmark.block_device
                || dma.block_device_generation != benchmark.block_device_generation
                || dma.block_range != benchmark.block_range
                || dma.block_range_generation != benchmark.block_range_generation
                || dma.byte_len != write_path.completed_bytes
            {
                return Err(SemanticInvariantError::BlockBenchmarkMetricMismatch {
                    benchmark: benchmark.id,
                });
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == benchmark.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockBenchmarkRecorded {
                            benchmark: id,
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
                            iops,
                            throughput_bytes_per_sec,
                            p50_latency_nanos,
                            p99_latency_nanos,
                            generation,
                        } if *id == benchmark.id
                            && *backend == benchmark.backend
                            && *block_device == benchmark.block_device
                            && *block_device_generation == benchmark.block_device_generation
                            && *block_range == benchmark.block_range
                            && *block_range_generation == benchmark.block_range_generation
                            && *read_path == benchmark.read_path
                            && *read_path_generation == benchmark.read_path_generation
                            && *write_path == benchmark.write_path
                            && *write_path_generation == benchmark.write_path_generation
                            && *request_queue == benchmark.request_queue
                            && *request_queue_generation == benchmark.request_queue_generation
                            && *block_dma_buffer == benchmark.block_dma_buffer
                            && *block_dma_buffer_generation == benchmark.block_dma_buffer_generation
                            && *sample_requests == benchmark.sample_requests
                            && *sample_bytes == benchmark.sample_bytes
                            && *read_completed_requests == benchmark.read_completed_requests
                            && *write_completed_requests == benchmark.write_completed_requests
                            && *queue_completed_requests == benchmark.queue_completed_requests
                            && *measured_nanos == benchmark.measured_nanos
                            && *budget_nanos == benchmark.budget_nanos
                            && *iops == benchmark.iops
                            && *throughput_bytes_per_sec == benchmark.throughput_bytes_per_sec
                            && *p50_latency_nanos == benchmark.p50_latency_nanos
                            && *p99_latency_nanos == benchmark.p99_latency_nanos
                            && *generation == benchmark.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockBenchmarkMissingEvent {
                    benchmark: benchmark.id,
                    event: benchmark.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_benchmark_iops_for_test(
        &mut self,
        benchmark: BlockBenchmarkId,
        iops: u64,
    ) {
        if let Some(record) = self
            .block_benchmarks
            .iter_mut()
            .find(|record| record.id == benchmark)
        {
            record.iops = iops;
        }
    }
}
