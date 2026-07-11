use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_network_disk_io(
        &self,
        integrated: IntegratedNetworkDiskIoId,
        scenario: &str,
        network_benchmark: NetworkBenchmarkId,
        network_benchmark_generation: Generation,
        block_benchmark: BlockBenchmarkId,
        block_benchmark_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated network/disk IO id=0 is invalid");
        }
        if self
            .domains
            .integrated
            .integrated_network_disk_ios
            .iter()
            .any(|record| record.id == integrated)
        {
            return Err("integrated network/disk IO evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated network/disk IO scenario is empty");
        }
        if network_benchmark_generation == 0
            || block_benchmark_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated network/disk IO refs must carry generations");
        }

        let Some(network) = self.domains.network.network_benchmarks.iter().find(|record| {
            record.id == network_benchmark && record.generation == network_benchmark_generation
        }) else {
            return Err("integrated network/disk IO missing network benchmark evidence");
        };
        let Some(block) = self.domains.block.block_benchmarks.iter().find(|record| {
            record.id == block_benchmark && record.generation == block_benchmark_generation
        }) else {
            return Err("integrated network/disk IO missing block benchmark evidence");
        };
        if network.state != NetworkBenchmarkState::Recorded
            || block.state != BlockBenchmarkState::Recorded
            || network.sample_bytes == 0
            || block.sample_bytes == 0
            || network.sample_packets == 0
            || block.sample_requests == 0
            || network.measured_nanos == 0
            || block.measured_nanos == 0
            || network.measured_nanos > network.budget_nanos
            || block.measured_nanos > block.budget_nanos
            || network.p99_latency_nanos == 0
            || block.p99_latency_nanos == 0
        {
            return Err("integrated network/disk IO requires recorded benchmark evidence");
        }
        if network.tx_completed_packets == 0
            || network.rx_resolved_packets == 0
            || block.read_completed_requests == 0
            || block.write_completed_requests == 0
            || block.queue_completed_requests != block.sample_requests
        {
            return Err("integrated network/disk IO benchmark accounting is not closed");
        }
        if network.adapter_generation == 0
            || network.packet_device_generation == 0
            || network.socket_generation == 0
            || network.owner_store_generation == 0
            || block.backend.generation == 0
            || block.block_device_generation == 0
            || block.request_queue_generation == 0
            || block.block_dma_buffer_generation == 0
        {
            return Err("integrated network/disk IO benchmark refs must be generation exact");
        }
        if block.backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("integrated network/disk IO requires semantic block backend evidence");
        }
        let Some(total_bytes) = network.sample_bytes.checked_add(block.sample_bytes) else {
            return Err("integrated network/disk IO byte accounting overflow");
        };
        let concurrent_window_nanos = network.measured_nanos.max(block.measured_nanos);
        if Self::derive_integrated_io_throughput_bytes_per_sec(total_bytes, concurrent_window_nanos)
            .is_none()
        {
            return Err("integrated network/disk IO throughput overflow");
        }
        Ok(())
    }

    const fn derive_integrated_io_throughput_bytes_per_sec(bytes: u64, nanos: u64) -> Option<u64> {
        if nanos == 0 {
            return None;
        }
        match bytes.checked_mul(1_000_000_000) {
            Some(scaled) => Some(scaled / nanos),
            None => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_network_disk_io_with_id(
        &mut self,
        integrated: IntegratedNetworkDiskIoId,
        scenario: &str,
        network_benchmark: NetworkBenchmarkId,
        network_benchmark_generation: Generation,
        block_benchmark: BlockBenchmarkId,
        block_benchmark_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_network_disk_io(
                integrated,
                scenario,
                network_benchmark,
                network_benchmark_generation,
                block_benchmark,
                block_benchmark_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(network) = self.domains.network.network_benchmarks.iter().find(|record| {
            record.id == network_benchmark && record.generation == network_benchmark_generation
        }) else {
            return false;
        };
        let Some(block) = self.domains.block.block_benchmarks.iter().find(|record| {
            record.id == block_benchmark && record.generation == block_benchmark_generation
        }) else {
            return false;
        };
        let Some(total_bytes) = network.sample_bytes.checked_add(block.sample_bytes) else {
            return false;
        };
        let concurrent_window_nanos = network.measured_nanos.max(block.measured_nanos);
        let Some(combined_throughput_bytes_per_sec) =
            Self::derive_integrated_io_throughput_bytes_per_sec(
                total_bytes,
                concurrent_window_nanos,
            )
        else {
            return false;
        };
        let max_p99_latency_nanos = network.p99_latency_nanos.max(block.p99_latency_nanos);
        let generation = 1;
        self.domains.integrated.next_integrated_network_disk_io_id = self
            .domains
            .integrated
            .next_integrated_network_disk_io_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedNetworkDiskIoRecorded {
                scenario: scenario.to_string(),
                integrated,
                network_benchmark,
                network_benchmark_generation,
                block_benchmark,
                block_benchmark_generation,
                network_owner_store: network.owner_store,
                network_owner_store_generation: network.owner_store_generation,
                packet_device: network.packet_device,
                packet_device_generation: network.packet_device_generation,
                block_device: block.block_device,
                block_device_generation: block.block_device_generation,
                network_sample_bytes: network.sample_bytes,
                block_sample_bytes: block.sample_bytes,
                concurrent_window_nanos,
                combined_throughput_bytes_per_sec,
                max_p99_latency_nanos,
                invariant_checks,
                generation,
            },
        );
        self.domains.integrated.integrated_network_disk_ios.push(IntegratedNetworkDiskIoRecord {
            id: integrated,
            scenario: scenario.to_string(),
            network_benchmark,
            network_benchmark_generation,
            block_benchmark,
            block_benchmark_generation,
            network_owner_store: network.owner_store,
            network_owner_store_generation: network.owner_store_generation,
            network_adapter: network.adapter,
            network_adapter_generation: network.adapter_generation,
            packet_device: network.packet_device,
            packet_device_generation: network.packet_device_generation,
            socket: network.socket,
            socket_generation: network.socket_generation,
            block_backend: block.backend,
            block_device: block.block_device,
            block_device_generation: block.block_device_generation,
            block_request_queue: block.request_queue,
            block_request_queue_generation: block.request_queue_generation,
            block_dma_buffer: block.block_dma_buffer,
            block_dma_buffer_generation: block.block_dma_buffer_generation,
            network_sample_bytes: network.sample_bytes,
            block_sample_bytes: block.sample_bytes,
            network_sample_packets: network.sample_packets,
            block_sample_requests: block.sample_requests,
            concurrent_window_nanos,
            combined_throughput_bytes_per_sec,
            max_p99_latency_nanos,
            invariant_checks,
            generation,
            state: IntegratedNetworkDiskIoState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn integrated_network_disk_ios(&self) -> &[IntegratedNetworkDiskIoRecord] {
        &self.domains.integrated.integrated_network_disk_ios
    }

    pub fn integrated_network_disk_io_count(&self) -> usize {
        self.domains.integrated.integrated_network_disk_ios.len()
    }

    pub fn check_integrated_network_disk_io_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.integrated.integrated_network_disk_ios {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedNetworkDiskIoState::Recorded
                || record.network_benchmark_generation == 0
                || record.block_benchmark_generation == 0
                || record.network_owner_store_generation == 0
                || record.network_adapter_generation == 0
                || record.packet_device_generation == 0
                || record.socket_generation == 0
                || record.block_backend.generation == 0
                || record.block_device_generation == 0
                || record.block_request_queue_generation == 0
                || record.block_dma_buffer_generation == 0
                || record.network_sample_bytes == 0
                || record.block_sample_bytes == 0
                || record.network_sample_packets == 0
                || record.block_sample_requests == 0
                || record.concurrent_window_nanos == 0
                || record.combined_throughput_bytes_per_sec == 0
                || record.max_p99_latency_nanos == 0
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedNetworkDiskIoInvalid {
                    integrated: record.id,
                });
            }
            for (label, id, generation, refs) in [
                (
                    "network-benchmark",
                    record.network_benchmark,
                    record.network_benchmark_generation,
                    self.domains
                        .network
                        .network_benchmarks
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "block-benchmark",
                    record.block_benchmark,
                    record.block_benchmark_generation,
                    self.domains
                        .block
                        .block_benchmarks
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
            ] {
                if id == 0
                    || generation == 0
                    || !refs.into_iter().any(|item| item == (id, generation))
                {
                    return Err(SemanticInvariantError::IntegratedNetworkDiskIoMissingEvidence {
                        integrated: record.id,
                        evidence: label,
                    });
                }
            }
            if self
                .validate_integrated_network_disk_io(
                    u64::MAX,
                    &record.scenario,
                    record.network_benchmark,
                    record.network_benchmark_generation,
                    record.block_benchmark,
                    record.block_benchmark_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedNetworkDiskIoInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedNetworkDiskIoRecorded {
                            scenario,
                            integrated,
                            network_benchmark,
                            network_benchmark_generation,
                            block_benchmark,
                            block_benchmark_generation,
                            network_owner_store,
                            network_owner_store_generation,
                            packet_device,
                            packet_device_generation,
                            block_device,
                            block_device_generation,
                            network_sample_bytes,
                            block_sample_bytes,
                            concurrent_window_nanos,
                            combined_throughput_bytes_per_sec,
                            max_p99_latency_nanos,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *network_benchmark == record.network_benchmark
                            && *network_benchmark_generation == record.network_benchmark_generation
                            && *block_benchmark == record.block_benchmark
                            && *block_benchmark_generation == record.block_benchmark_generation
                            && *network_owner_store == record.network_owner_store
                            && *network_owner_store_generation
                                == record.network_owner_store_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *network_sample_bytes == record.network_sample_bytes
                            && *block_sample_bytes == record.block_sample_bytes
                            && *concurrent_window_nanos == record.concurrent_window_nanos
                            && *combined_throughput_bytes_per_sec
                                == record.combined_throughput_bytes_per_sec
                            && *max_p99_latency_nanos == record.max_p99_latency_nanos
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IntegratedNetworkDiskIoMissingEvent {
                    integrated: record.id,
                });
            }
        }
        Ok(())
    }
}
