use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_network_benchmark(
        &self,
        benchmark: NetworkBenchmarkId,
        scenario: &str,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_completion: NetworkTxCompletionId,
        tx_completion_generation: Generation,
        rx_wait_resolution: NetworkRxWaitResolutionId,
        rx_wait_resolution_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        backpressure: Option<NetworkBackpressureId>,
        backpressure_generation: Option<Generation>,
        sample_packets: u32,
        sample_bytes: u64,
        tx_completed_packets: u32,
        rx_resolved_packets: u32,
        dropped_packets: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("network benchmark id=0 is invalid");
        }
        if benchmark == u64::MAX {
            return Err("network benchmark id cannot advance generation cursor");
        }
        if self.network_benchmarks.iter().any(|record| record.id == benchmark) {
            return Err("network benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("network benchmark scenario is empty");
        }
        if backpressure.is_some() != backpressure_generation.is_some() {
            return Err("network benchmark backpressure generation is incomplete");
        }
        if sample_packets == 0
            || sample_bytes == 0
            || measured_nanos == 0
            || budget_nanos == 0
            || p50_latency_nanos == 0
            || p99_latency_nanos == 0
        {
            return Err("network benchmark metrics require nonzero samples and timing");
        }
        if measured_nanos > budget_nanos {
            return Err("network benchmark exceeds latency budget");
        }
        if p99_latency_nanos < p50_latency_nanos || p99_latency_nanos > measured_nanos {
            return Err("network benchmark latency distribution is invalid");
        }
        let Some(accounted_packets) = tx_completed_packets
            .checked_add(rx_resolved_packets)
            .and_then(|count| count.checked_add(dropped_packets))
        else {
            return Err("network benchmark packet accounting overflow");
        };
        if accounted_packets != sample_packets {
            return Err("network benchmark packet accounting is not closed");
        }
        if tx_completed_packets == 0 || rx_resolved_packets == 0 {
            return Err("network benchmark requires both tx and rx evidence");
        }
        if Self::derive_network_throughput_bytes_per_sec(sample_bytes, measured_nanos).is_none() {
            return Err("network benchmark throughput overflow");
        }

        let Some(adapter_record) = self.network_stack_adapters.iter().find(|record| {
            record.id == adapter
                && record.generation == adapter_generation
                && record.state == NetworkStackAdapterState::Bound
        }) else {
            return Err("network benchmark adapter generation is missing or inactive");
        };
        if adapter_record.packet_device != packet_device
            || adapter_record.packet_device_generation != packet_device_generation
            || adapter_record.tx_queue != tx_queue
            || adapter_record.tx_queue_generation != tx_queue_generation
            || adapter_record.rx_queue != rx_queue
            || adapter_record.rx_queue_generation != rx_queue_generation
        {
            return Err("network benchmark adapter references do not match");
        }

        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network benchmark packet device generation is missing or inactive");
        };
        let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == tx_queue
                && record.generation == tx_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network benchmark tx queue generation is missing or inactive");
        };
        let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == rx_queue
                && record.generation == rx_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network benchmark rx queue generation is missing or inactive");
        };
        if tx_queue_record.role != PacketQueueRole::Tx
            || rx_queue_record.role != PacketQueueRole::Rx
            || tx_queue_record.packet_device != packet_device_record.id
            || tx_queue_record.packet_device_generation != packet_device_record.generation
            || rx_queue_record.packet_device != packet_device_record.id
            || rx_queue_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network benchmark queues do not match packet device roles");
        }

        let Some(tx_completion_record) = self.network_tx_completions.iter().find(|record| {
            record.id == tx_completion
                && record.generation == tx_completion_generation
                && record.state == NetworkTxCompletionState::Completed
        }) else {
            return Err("network benchmark tx completion generation is missing or inactive");
        };
        if tx_completion_record.packet_device != packet_device
            || tx_completion_record.packet_device_generation != packet_device_generation
            || tx_completion_record.tx_queue != tx_queue
            || tx_completion_record.tx_queue_generation != tx_queue_generation
            || sample_bytes < tx_completion_record.byte_len as u64
        {
            return Err("network benchmark tx completion does not match packet evidence");
        }

        let Some(rx_resolution_record) = self.network_rx_wait_resolutions.iter().find(|record| {
            record.id == rx_wait_resolution
                && record.generation == rx_wait_resolution_generation
                && record.state == NetworkRxWaitResolutionState::Resolved
        }) else {
            return Err("network benchmark rx wait resolution generation is missing or inactive");
        };
        if rx_resolution_record.packet_device != packet_device
            || rx_resolution_record.packet_device_generation != packet_device_generation
            || rx_resolution_record.rx_queue != rx_queue
            || rx_resolution_record.rx_queue_generation != rx_queue_generation
            || rx_resolution_record.ready_descriptors as u32 != rx_resolved_packets
        {
            return Err("network benchmark rx resolution does not match packet evidence");
        }

        let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
            record.id == endpoint
                && record.generation == endpoint_generation
                && record.state == EndpointObjectState::Allocated
        }) else {
            return Err("network benchmark endpoint generation is missing or inactive");
        };
        if endpoint_record.adapter != adapter
            || endpoint_record.adapter_generation != adapter_generation
        {
            return Err("network benchmark endpoint adapter does not match");
        }
        let Some(socket_record) = self.socket_objects.iter().find(|record| {
            record.id == endpoint_record.socket
                && record.generation == endpoint_record.socket_generation
                && record.state == SocketObjectState::Created
        }) else {
            return Err("network benchmark socket generation is missing or inactive");
        };
        if socket_record.adapter != adapter
            || socket_record.adapter_generation != adapter_generation
            || socket_record.owner_store != endpoint_record.owner_store
            || socket_record.owner_store_generation != endpoint_record.owner_store_generation
        {
            return Err("network benchmark socket references do not match endpoint");
        }
        let Some(store_record) = self.domains.lifecycle.stores.iter().find(|record| {
            record.id == endpoint_record.owner_store
                && record.generation == endpoint_record.owner_store_generation
        }) else {
            return Err("network benchmark owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("network benchmark owner store is dead");
        }

        if let (Some(backpressure), Some(backpressure_generation)) =
            (backpressure, backpressure_generation)
        {
            let Some(backpressure_record) = self.network_backpressures.iter().find(|record| {
                record.id == backpressure
                    && record.generation == backpressure_generation
                    && record.state == NetworkBackpressureState::Recorded
            }) else {
                return Err("network benchmark backpressure generation is missing or inactive");
            };
            if backpressure_record.adapter != adapter
                || backpressure_record.adapter_generation != adapter_generation
                || backpressure_record.packet_device != packet_device
                || backpressure_record.packet_device_generation != packet_device_generation
                || backpressure_record.dropped_packets != dropped_packets
                || sample_bytes < backpressure_record.dropped_bytes as u64
            {
                return Err("network benchmark backpressure evidence does not match");
            }
        } else if dropped_packets != 0 {
            return Err("network benchmark dropped packets require backpressure evidence");
        }

        if self.check_invariants().is_err() {
            return Err("network benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_network_benchmark_with_id(
        &mut self,
        benchmark: NetworkBenchmarkId,
        scenario: &str,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        tx_queue: PacketQueueObjectId,
        tx_queue_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        tx_completion: NetworkTxCompletionId,
        tx_completion_generation: Generation,
        rx_wait_resolution: NetworkRxWaitResolutionId,
        rx_wait_resolution_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        backpressure: Option<NetworkBackpressureId>,
        backpressure_generation: Option<Generation>,
        sample_packets: u32,
        sample_bytes: u64,
        tx_completed_packets: u32,
        rx_resolved_packets: u32,
        dropped_packets: u32,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_benchmark(
                benchmark,
                scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
            )
            .is_err()
        {
            return false;
        }
        let Some(endpoint_record) = self
            .endpoint_objects
            .iter()
            .find(|record| record.id == endpoint && record.generation == endpoint_generation)
        else {
            return false;
        };
        let socket = endpoint_record.socket;
        let socket_generation = endpoint_record.socket_generation;
        let owner_store = endpoint_record.owner_store;
        let owner_store_generation = endpoint_record.owner_store_generation;
        let Some(throughput_bytes_per_sec) =
            Self::derive_network_throughput_bytes_per_sec(sample_bytes, measured_nanos)
        else {
            return false;
        };
        let generation = 1;
        self.next_network_benchmark_id =
            self.next_network_benchmark_id.max(benchmark.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkBenchmarkRecorded {
                benchmark,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                throughput_bytes_per_sec,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            },
        );
        self.network_benchmarks.push(NetworkBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            tx_queue,
            tx_queue_generation,
            rx_queue,
            rx_queue_generation,
            tx_completion,
            tx_completion_generation,
            rx_wait_resolution,
            rx_wait_resolution_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            backpressure,
            backpressure_generation,
            sample_packets,
            sample_bytes,
            tx_completed_packets,
            rx_resolved_packets,
            dropped_packets,
            measured_nanos,
            budget_nanos,
            throughput_bytes_per_sec,
            p50_latency_nanos,
            p99_latency_nanos,
            generation,
            state: NetworkBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_benchmarks(&self) -> &[NetworkBenchmarkRecord] {
        &self.network_benchmarks
    }

    pub fn network_benchmark_count(&self) -> usize {
        self.network_benchmarks.len()
    }

    pub fn derive_network_throughput_bytes_per_sec(
        sample_bytes: u64,
        measured_nanos: u64,
    ) -> Option<u64> {
        sample_bytes.checked_mul(1_000_000_000)?.checked_div(measured_nanos)
    }

    pub fn check_network_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.network_benchmarks {
            let expected_throughput = Self::derive_network_throughput_bytes_per_sec(
                record.sample_bytes,
                record.measured_nanos,
            );
            let accounted_packets = record
                .tx_completed_packets
                .checked_add(record.rx_resolved_packets)
                .and_then(|count| count.checked_add(record.dropped_packets));
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.adapter_generation == 0
                || record.packet_device_generation == 0
                || record.tx_queue_generation == 0
                || record.rx_queue_generation == 0
                || record.tx_completion_generation == 0
                || record.rx_wait_resolution_generation == 0
                || record.endpoint_generation == 0
                || record.socket_generation == 0
                || record.owner_store_generation == 0
                || record.backpressure.is_some() != record.backpressure_generation.is_some()
                || record.sample_packets == 0
                || record.sample_bytes == 0
                || record.tx_completed_packets == 0
                || record.rx_resolved_packets == 0
                || accounted_packets != Some(record.sample_packets)
                || record.measured_nanos == 0
                || record.budget_nanos == 0
                || record.measured_nanos > record.budget_nanos
                || expected_throughput != Some(record.throughput_bytes_per_sec)
                || record.p50_latency_nanos == 0
                || record.p99_latency_nanos < record.p50_latency_nanos
                || record.p99_latency_nanos > record.measured_nanos
                || record.state != NetworkBenchmarkState::Recorded
            {
                return Err(SemanticInvariantError::NetworkBenchmarkInvalid {
                    benchmark: record.id,
                });
            }

            let Some(adapter) = self.network_stack_adapters.iter().find(|adapter| {
                adapter.id == record.adapter && adapter.generation == record.adapter_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkStackAdapter,
                        record.adapter,
                        record.adapter_generation,
                    ),
                });
            };
            let Some(packet_device) = self.packet_device_objects.iter().find(|packet_device| {
                packet_device.id == record.packet_device
                    && packet_device.generation == record.packet_device_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketDeviceObject,
                        record.packet_device,
                        record.packet_device_generation,
                    ),
                });
            };
            let Some(tx_queue) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.tx_queue && queue.generation == record.tx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketQueueObject,
                        record.tx_queue,
                        record.tx_queue_generation,
                    ),
                });
            };
            let Some(rx_queue) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.rx_queue && queue.generation == record.rx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketQueueObject,
                        record.rx_queue,
                        record.rx_queue_generation,
                    ),
                });
            };
            if adapter.state != NetworkStackAdapterState::Bound
                || packet_device.state != PacketDeviceObjectState::Registered
                || tx_queue.state != PacketQueueObjectState::Registered
                || rx_queue.state != PacketQueueObjectState::Registered
                || tx_queue.role != PacketQueueRole::Tx
                || rx_queue.role != PacketQueueRole::Rx
                || adapter.packet_device != record.packet_device
                || adapter.packet_device_generation != record.packet_device_generation
                || adapter.tx_queue != record.tx_queue
                || adapter.tx_queue_generation != record.tx_queue_generation
                || adapter.rx_queue != record.rx_queue
                || adapter.rx_queue_generation != record.rx_queue_generation
                || tx_queue.packet_device != record.packet_device
                || tx_queue.packet_device_generation != record.packet_device_generation
                || rx_queue.packet_device != record.packet_device
                || rx_queue.packet_device_generation != record.packet_device_generation
            {
                return Err(SemanticInvariantError::NetworkBenchmarkInvalid {
                    benchmark: record.id,
                });
            }

            let Some(tx_completion) = self.network_tx_completions.iter().find(|completion| {
                completion.id == record.tx_completion
                    && completion.generation == record.tx_completion_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkTxCompletion,
                        record.tx_completion,
                        record.tx_completion_generation,
                    ),
                });
            };
            if tx_completion.state != NetworkTxCompletionState::Completed
                || tx_completion.packet_device != record.packet_device
                || tx_completion.packet_device_generation != record.packet_device_generation
                || tx_completion.tx_queue != record.tx_queue
                || tx_completion.tx_queue_generation != record.tx_queue_generation
                || record.sample_bytes < tx_completion.byte_len as u64
            {
                return Err(SemanticInvariantError::NetworkBenchmarkMetricMismatch {
                    benchmark: record.id,
                });
            }

            let Some(rx_resolution) = self.network_rx_wait_resolutions.iter().find(|resolution| {
                resolution.id == record.rx_wait_resolution
                    && resolution.generation == record.rx_wait_resolution_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkRxWaitResolution,
                        record.rx_wait_resolution,
                        record.rx_wait_resolution_generation,
                    ),
                });
            };
            if rx_resolution.state != NetworkRxWaitResolutionState::Resolved
                || rx_resolution.packet_device != record.packet_device
                || rx_resolution.packet_device_generation != record.packet_device_generation
                || rx_resolution.rx_queue != record.rx_queue
                || rx_resolution.rx_queue_generation != record.rx_queue_generation
                || rx_resolution.ready_descriptors as u32 != record.rx_resolved_packets
            {
                return Err(SemanticInvariantError::NetworkBenchmarkMetricMismatch {
                    benchmark: record.id,
                });
            }

            let Some(endpoint) = self.endpoint_objects.iter().find(|endpoint| {
                endpoint.id == record.endpoint && endpoint.generation == record.endpoint_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::EndpointObject,
                        record.endpoint,
                        record.endpoint_generation,
                    ),
                });
            };
            let Some(socket) = self.socket_objects.iter().find(|socket| {
                socket.id == record.socket && socket.generation == record.socket_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::SocketObject,
                        record.socket,
                        record.socket_generation,
                    ),
                });
            };
            let Some(store) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::Store,
                        record.owner_store,
                        record.owner_store_generation,
                    ),
                });
            };
            if endpoint.state != EndpointObjectState::Allocated
                || socket.state != SocketObjectState::Created
                || store.state == StoreState::Dead
                || endpoint.socket != record.socket
                || endpoint.socket_generation != record.socket_generation
                || endpoint.adapter != record.adapter
                || endpoint.adapter_generation != record.adapter_generation
                || endpoint.owner_store != record.owner_store
                || endpoint.owner_store_generation != record.owner_store_generation
                || socket.adapter != record.adapter
                || socket.adapter_generation != record.adapter_generation
                || socket.owner_store != record.owner_store
                || socket.owner_store_generation != record.owner_store_generation
            {
                return Err(SemanticInvariantError::NetworkBenchmarkInvalid {
                    benchmark: record.id,
                });
            }

            if let (Some(backpressure), Some(backpressure_generation)) =
                (record.backpressure, record.backpressure_generation)
            {
                let Some(backpressure_record) =
                    self.network_backpressures.iter().find(|backpressure_record| {
                        backpressure_record.id == backpressure
                            && backpressure_record.generation == backpressure_generation
                    })
                else {
                    return Err(SemanticInvariantError::NetworkBenchmarkMissingTarget {
                        benchmark: record.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::NetworkBackpressure,
                            backpressure,
                            backpressure_generation,
                        ),
                    });
                };
                if backpressure_record.state != NetworkBackpressureState::Recorded
                    || backpressure_record.adapter != record.adapter
                    || backpressure_record.adapter_generation != record.adapter_generation
                    || backpressure_record.packet_device != record.packet_device
                    || backpressure_record.packet_device_generation
                        != record.packet_device_generation
                    || backpressure_record.dropped_packets != record.dropped_packets
                    || record.sample_bytes < backpressure_record.dropped_bytes as u64
                {
                    return Err(SemanticInvariantError::NetworkBenchmarkMetricMismatch {
                        benchmark: record.id,
                    });
                }
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkBenchmarkRecorded {
                            benchmark,
                            adapter,
                            adapter_generation,
                            packet_device,
                            packet_device_generation,
                            tx_completion,
                            tx_completion_generation,
                            rx_wait_resolution,
                            rx_wait_resolution_generation,
                            endpoint,
                            endpoint_generation,
                            socket,
                            socket_generation,
                            owner_store,
                            owner_store_generation,
                            sample_packets,
                            sample_bytes,
                            tx_completed_packets,
                            rx_resolved_packets,
                            dropped_packets,
                            measured_nanos,
                            budget_nanos,
                            throughput_bytes_per_sec,
                            p50_latency_nanos,
                            p99_latency_nanos,
                            generation,
                        } if *benchmark == record.id
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *tx_completion == record.tx_completion
                            && *tx_completion_generation == record.tx_completion_generation
                            && *rx_wait_resolution == record.rx_wait_resolution
                            && *rx_wait_resolution_generation == record.rx_wait_resolution_generation
                            && *endpoint == record.endpoint
                            && *endpoint_generation == record.endpoint_generation
                            && *socket == record.socket
                            && *socket_generation == record.socket_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *sample_packets == record.sample_packets
                            && *sample_bytes == record.sample_bytes
                            && *tx_completed_packets == record.tx_completed_packets
                            && *rx_resolved_packets == record.rx_resolved_packets
                            && *dropped_packets == record.dropped_packets
                            && *measured_nanos == record.measured_nanos
                            && *budget_nanos == record.budget_nanos
                            && *throughput_bytes_per_sec == record.throughput_bytes_per_sec
                            && *p50_latency_nanos == record.p50_latency_nanos
                            && *p99_latency_nanos == record.p99_latency_nanos
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkBenchmarkMissingEvent {
                    benchmark: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_benchmark_throughput_for_test(
        &mut self,
        benchmark: NetworkBenchmarkId,
        throughput_bytes_per_sec: u64,
    ) {
        if let Some(record) =
            self.network_benchmarks.iter_mut().find(|record| record.id == benchmark)
        {
            record.throughput_bytes_per_sec = throughput_bytes_per_sec;
        }
    }
}
