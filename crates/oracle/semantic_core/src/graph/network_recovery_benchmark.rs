use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_network_recovery_benchmark(
        &self,
        benchmark: NetworkRecoveryBenchmarkId,
        scenario: &str,
        cleanup: NetworkDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        fault_injection: Option<NetworkFaultInjectionId>,
        fault_injection_generation: Option<Generation>,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_socket_waits: u32,
        revoked_packet_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("network recovery benchmark id=0 is invalid");
        }
        if benchmark == u64::MAX {
            return Err("network recovery benchmark id cannot advance generation cursor");
        }
        if self
            .domains
            .network
            .network_recovery_benchmarks
            .iter()
            .any(|record| record.id == benchmark)
        {
            return Err("network recovery benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("network recovery benchmark scenario is empty");
        }
        if fault_injection.is_some() != fault_injection_generation.is_some() {
            return Err("network recovery benchmark fault injection generation is incomplete");
        }
        if recovery_start_event == 0 || recovery_complete_event == 0 {
            return Err("network recovery benchmark event ids are invalid");
        }
        if recovery_start_event >= recovery_complete_event {
            return Err("network recovery benchmark event order is invalid");
        }
        if recovery_nanos == 0 || budget_nanos == 0 {
            return Err("network recovery benchmark timing is empty");
        }
        if recovery_nanos > budget_nanos {
            return Err("network recovery benchmark exceeds recovery budget");
        }
        if cancelled_socket_waits == 0 && revoked_packet_capabilities == 0 {
            return Err("network recovery benchmark requires cleanup effects");
        }

        let Some(cleanup_record) =
            self.domains.network.network_driver_cleanups.iter().find(|record| {
                record.id == cleanup
                    && record.generation == cleanup_generation
                    && record.state == NetworkDriverCleanupState::Completed
            })
        else {
            return Err("network recovery benchmark cleanup generation is missing or incomplete");
        };
        let Some(cleanup_completed_at_event) = cleanup_record.completed_at_event else {
            return Err("network recovery benchmark cleanup completion event is missing");
        };
        if cleanup_record.io_cleanup != io_cleanup
            || cleanup_record.io_cleanup_generation != io_cleanup_generation
            || cleanup_record.started_at_event != recovery_start_event
            || cleanup_completed_at_event != recovery_complete_event
        {
            return Err("network recovery benchmark cleanup references do not match");
        }
        if cleanup_record.cancelled_socket_waits.len() > u32::MAX as usize
            || cleanup_record.revoked_packet_capabilities.len() > u32::MAX as usize
            || cleanup_record.cancelled_socket_waits.len() as u32 != cancelled_socket_waits
            || cleanup_record.revoked_packet_capabilities.len() as u32
                != revoked_packet_capabilities
        {
            return Err("network recovery benchmark cleanup effect counts do not match");
        }

        if let (Some(fault_injection), Some(fault_injection_generation)) =
            (fault_injection, fault_injection_generation)
        {
            let Some(injection_record) =
                self.domains.network.network_fault_injections.iter().find(|record| {
                    record.id == fault_injection
                        && record.generation == fault_injection_generation
                        && record.state == NetworkFaultInjectionState::Recorded
                })
            else {
                return Err("network recovery benchmark fault injection generation is missing");
            };
            if injection_record.adapter != cleanup_record.adapter
                || injection_record.adapter_generation != cleanup_record.adapter_generation
                || injection_record.packet_device != cleanup_record.packet_device
                || injection_record.packet_device_generation
                    != cleanup_record.packet_device_generation
                || injection_record.recorded_at_event >= cleanup_record.started_at_event
            {
                return Err("network recovery benchmark fault injection does not precede cleanup");
            }
        }

        if self.check_invariants().is_err() {
            return Err("network recovery benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_network_recovery_benchmark_with_id(
        &mut self,
        benchmark: NetworkRecoveryBenchmarkId,
        scenario: &str,
        cleanup: NetworkDriverCleanupId,
        cleanup_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        fault_injection: Option<NetworkFaultInjectionId>,
        fault_injection_generation: Option<Generation>,
        recovery_start_event: EventId,
        recovery_complete_event: EventId,
        cancelled_socket_waits: u32,
        revoked_packet_capabilities: u32,
        recovery_nanos: u64,
        budget_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_recovery_benchmark(
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
            )
            .is_err()
        {
            return false;
        }

        let Some(cleanup_record) = self
            .domains
            .network
            .network_driver_cleanups
            .iter()
            .find(|record| record.id == cleanup && record.generation == cleanup_generation)
        else {
            return false;
        };
        let adapter = cleanup_record.adapter;
        let adapter_generation = cleanup_record.adapter_generation;
        let packet_device = cleanup_record.packet_device;
        let packet_device_generation = cleanup_record.packet_device_generation;
        let backend = cleanup_record.backend;
        let driver_store = cleanup_record.driver_store;
        let driver_store_generation = cleanup_record.driver_store_generation;
        let generation = 1;
        self.domains.network.next_network_recovery_benchmark_id = self
            .domains
            .network
            .next_network_recovery_benchmark_id
            .max(benchmark.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkRecoveryBenchmarkRecorded {
                benchmark,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                driver_store,
                driver_store_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                generation,
            },
        );
        self.domains.network.network_recovery_benchmarks.push(NetworkRecoveryBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
            cleanup,
            cleanup_generation,
            io_cleanup,
            io_cleanup_generation,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            backend,
            driver_store,
            driver_store_generation,
            fault_injection,
            fault_injection_generation,
            recovery_start_event,
            recovery_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos,
            budget_nanos,
            generation,
            state: NetworkRecoveryBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_recovery_benchmarks(&self) -> &[NetworkRecoveryBenchmarkRecord] {
        &self.domains.network.network_recovery_benchmarks
    }

    pub fn network_recovery_benchmark_count(&self) -> usize {
        self.domains.network.network_recovery_benchmarks.len()
    }

    pub fn check_network_recovery_benchmark_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.network_recovery_benchmarks {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.cleanup_generation == 0
                || record.io_cleanup_generation == 0
                || record.adapter_generation == 0
                || record.packet_device_generation == 0
                || record.driver_store_generation == 0
                || record.fault_injection.is_some() != record.fault_injection_generation.is_some()
                || record.recovery_start_event == 0
                || record.recovery_complete_event == 0
                || record.recovery_start_event >= record.recovery_complete_event
                || record.cancelled_socket_waits == 0 && record.revoked_packet_capabilities == 0
                || record.recovery_nanos == 0
                || record.budget_nanos == 0
                || record.recovery_nanos > record.budget_nanos
                || record.state != NetworkRecoveryBenchmarkState::Recorded
            {
                return Err(SemanticInvariantError::NetworkRecoveryBenchmarkInvalid {
                    benchmark: record.id,
                });
            }

            let Some(cleanup) =
                self.domains.network.network_driver_cleanups.iter().find(|cleanup| {
                    cleanup.id == record.cleanup
                        && cleanup.generation == record.cleanup_generation
                        && cleanup.state == NetworkDriverCleanupState::Completed
                })
            else {
                return Err(SemanticInvariantError::NetworkRecoveryBenchmarkMissingTarget {
                    benchmark: record.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkDriverCleanup,
                        record.cleanup,
                        record.cleanup_generation,
                    ),
                });
            };
            let Some(completed_at_event) = cleanup.completed_at_event else {
                return Err(SemanticInvariantError::NetworkRecoveryBenchmarkInvalid {
                    benchmark: record.id,
                });
            };
            if cleanup.io_cleanup != record.io_cleanup
                || cleanup.io_cleanup_generation != record.io_cleanup_generation
                || cleanup.adapter != record.adapter
                || cleanup.adapter_generation != record.adapter_generation
                || cleanup.packet_device != record.packet_device
                || cleanup.packet_device_generation != record.packet_device_generation
                || cleanup.backend != record.backend
                || cleanup.driver_store != record.driver_store
                || cleanup.driver_store_generation != record.driver_store_generation
                || cleanup.started_at_event != record.recovery_start_event
                || completed_at_event != record.recovery_complete_event
                || cleanup.cancelled_socket_waits.len() > u32::MAX as usize
                || cleanup.revoked_packet_capabilities.len() > u32::MAX as usize
                || cleanup.cancelled_socket_waits.len() as u32 != record.cancelled_socket_waits
                || cleanup.revoked_packet_capabilities.len() as u32
                    != record.revoked_packet_capabilities
            {
                return Err(SemanticInvariantError::NetworkRecoveryBenchmarkMetricMismatch {
                    benchmark: record.id,
                });
            }

            if let (Some(fault_injection), Some(fault_injection_generation)) =
                (record.fault_injection, record.fault_injection_generation)
            {
                let Some(injection) =
                    self.domains.network.network_fault_injections.iter().find(|injection| {
                        injection.id == fault_injection
                            && injection.generation == fault_injection_generation
                            && injection.state == NetworkFaultInjectionState::Recorded
                    })
                else {
                    return Err(SemanticInvariantError::NetworkRecoveryBenchmarkMissingTarget {
                        benchmark: record.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::NetworkFaultInjection,
                            fault_injection,
                            fault_injection_generation,
                        ),
                    });
                };
                if injection.adapter != record.adapter
                    || injection.adapter_generation != record.adapter_generation
                    || injection.packet_device != record.packet_device
                    || injection.packet_device_generation != record.packet_device_generation
                    || injection.recorded_at_event >= cleanup.started_at_event
                {
                    return Err(SemanticInvariantError::NetworkRecoveryBenchmarkInvalid {
                        benchmark: record.id,
                    });
                }
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkRecoveryBenchmarkRecorded {
                            benchmark,
                            cleanup,
                            cleanup_generation,
                            io_cleanup,
                            io_cleanup_generation,
                            adapter,
                            adapter_generation,
                            packet_device,
                            packet_device_generation,
                            driver_store,
                            driver_store_generation,
                            fault_injection,
                            fault_injection_generation,
                            recovery_start_event,
                            recovery_complete_event,
                            cancelled_socket_waits,
                            revoked_packet_capabilities,
                            recovery_nanos,
                            budget_nanos,
                            generation,
                        } if *benchmark == record.id
                            && *cleanup == record.cleanup
                            && *cleanup_generation == record.cleanup_generation
                            && *io_cleanup == record.io_cleanup
                            && *io_cleanup_generation == record.io_cleanup_generation
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *fault_injection == record.fault_injection
                            && *fault_injection_generation == record.fault_injection_generation
                            && *recovery_start_event == record.recovery_start_event
                            && *recovery_complete_event == record.recovery_complete_event
                            && *cancelled_socket_waits == record.cancelled_socket_waits
                            && *revoked_packet_capabilities == record.revoked_packet_capabilities
                            && *recovery_nanos == record.recovery_nanos
                            && *budget_nanos == record.budget_nanos
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkRecoveryBenchmarkMissingEvent {
                    benchmark: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_recovery_benchmark_cleanup_generation_for_test(
        &mut self,
        benchmark: NetworkRecoveryBenchmarkId,
        cleanup_generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .network_recovery_benchmarks
            .iter_mut()
            .find(|record| record.id == benchmark)
        {
            record.cleanup_generation = cleanup_generation;
        }
    }
}
