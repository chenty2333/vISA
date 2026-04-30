use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_smp_network_fault(
        &self,
        integrated: IntegratedSmpNetworkFaultId,
        scenario: &str,
        network_driver_cleanup: NetworkDriverCleanupId,
        network_driver_cleanup_generation: Generation,
        smp_stress_run: SmpStressRunId,
        smp_stress_run_generation: Generation,
        remote_preempt: RemotePreemptId,
        remote_preempt_generation: Generation,
        smp_cleanup_quiescence: SmpCleanupQuiescenceId,
        smp_cleanup_quiescence_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated smp/network fault id=0 is invalid");
        }
        if self.integrated_smp_network_faults.iter().any(|record| record.id == integrated) {
            return Err("integrated smp/network fault evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated smp/network fault scenario is empty");
        }
        if network_driver_cleanup_generation == 0
            || smp_stress_run_generation == 0
            || remote_preempt_generation == 0
            || smp_cleanup_quiescence_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated smp/network fault refs must carry generations");
        }

        let Some(cleanup) = self.domains.network.network_driver_cleanups.iter().find(|record| {
            record.id == network_driver_cleanup
                && record.generation == network_driver_cleanup_generation
        }) else {
            return Err("integrated smp/network fault missing network cleanup evidence");
        };
        if cleanup.state != NetworkDriverCleanupState::Completed
            || cleanup.completed_at_event.is_none()
            || cleanup.cancelled_socket_waits.is_empty()
            || cleanup.cancelled_wait_tokens.is_empty()
            || cleanup.revoked_packet_capabilities.is_empty()
        {
            return Err("integrated smp/network fault requires completed network cleanup effects");
        }

        let Some(stress) = self.domains.scheduler.smp_stress_runs.iter().find(|record| {
            record.id == smp_stress_run && record.generation == smp_stress_run_generation
        }) else {
            return Err("integrated smp/network fault missing SMP stress evidence");
        };
        if stress.state != SmpStressRunState::Recorded
            || stress.property_failures != 0
            || stress.hart_count < 2
            || stress.observed_remote_preempt_count == 0
            || stress.observed_cleanup_quiescence_count == 0
            || stress.invariant_checks > invariant_checks
        {
            return Err("integrated smp/network fault requires clean SMP stress evidence");
        }

        let Some(remote) = self.domains.scheduler.remote_preempts.iter().find(|record| {
            record.id == remote_preempt && record.generation == remote_preempt_generation
        }) else {
            return Err("integrated smp/network fault missing remote preempt evidence");
        };
        if remote.state != RemotePreemptState::Applied
            || remote.source_hart == remote.target_hart
            || stress.last_remote_preempt != remote.id
            || stress.last_remote_preempt_generation != remote.generation
        {
            return Err("integrated smp/network fault remote preempt mismatch");
        }

        let Some(quiescence) =
            self.domains.scheduler.smp_cleanup_quiescence.iter().find(|record| {
                record.id == smp_cleanup_quiescence
                    && record.generation == smp_cleanup_quiescence_generation
            })
        else {
            return Err("integrated smp/network fault missing SMP quiescence evidence");
        };
        if quiescence.state != SmpCleanupQuiescenceState::Validated
            || quiescence.participants.len() < 2
            || quiescence.participants.iter().any(|participant| !participant.quiesced)
            || !quiescence.no_running_activation
            || !quiescence.no_pending_wait
            || !quiescence.no_live_capability
            || !quiescence.no_live_resource
            || stress.last_cleanup_quiescence != quiescence.id
            || stress.last_cleanup_quiescence_generation != quiescence.generation
        {
            return Err("integrated smp/network fault quiescence mismatch");
        }

        if self.domains.network.socket_waits.iter().any(|record| {
            record.adapter == cleanup.adapter
                && record.adapter_generation == cleanup.adapter_generation
                && record.state == SocketWaitState::Pending
        }) || self.domains.device.device_capabilities.iter().any(|record| {
            record.driver_store == cleanup.driver_store
                && record.driver_store_generation == cleanup.driver_store_generation
                && record.target
                    == ContractObjectRef::new(
                        ContractObjectKind::PacketDeviceObject,
                        cleanup.packet_device,
                        cleanup.packet_device_generation,
                    )
                && record.state == DeviceCapabilityState::Active
        }) {
            return Err("integrated smp/network fault found live network authority leak");
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_smp_network_fault_with_id(
        &mut self,
        integrated: IntegratedSmpNetworkFaultId,
        scenario: &str,
        network_driver_cleanup: NetworkDriverCleanupId,
        network_driver_cleanup_generation: Generation,
        smp_stress_run: SmpStressRunId,
        smp_stress_run_generation: Generation,
        remote_preempt: RemotePreemptId,
        remote_preempt_generation: Generation,
        smp_cleanup_quiescence: SmpCleanupQuiescenceId,
        smp_cleanup_quiescence_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_smp_network_fault(
                integrated,
                scenario,
                network_driver_cleanup,
                network_driver_cleanup_generation,
                smp_stress_run,
                smp_stress_run_generation,
                remote_preempt,
                remote_preempt_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(cleanup) = self.domains.network.network_driver_cleanups.iter().find(|record| {
            record.id == network_driver_cleanup
                && record.generation == network_driver_cleanup_generation
        }) else {
            return false;
        };
        let Some(stress) = self.domains.scheduler.smp_stress_runs.iter().find(|record| {
            record.id == smp_stress_run && record.generation == smp_stress_run_generation
        }) else {
            return false;
        };

        let driver_store = cleanup.driver_store;
        let driver_store_generation = cleanup.driver_store_generation;
        let packet_device = cleanup.packet_device;
        let packet_device_generation = cleanup.packet_device_generation;
        let adapter = cleanup.adapter;
        let adapter_generation = cleanup.adapter_generation;
        let backend = cleanup.backend;
        let io_cleanup = cleanup.io_cleanup;
        let io_cleanup_generation = cleanup.io_cleanup_generation;
        let cancelled_socket_wait_count = cleanup.cancelled_socket_waits.len() as u32;
        let cancelled_wait_token_count = cleanup.cancelled_wait_tokens.len() as u32;
        let revoked_packet_capability_count = cleanup.revoked_packet_capabilities.len() as u32;
        let hart_count = stress.hart_count;
        let generation = 1;
        self.next_integrated_smp_network_fault_id =
            self.next_integrated_smp_network_fault_id.max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedSmpNetworkFaultRecorded {
                scenario: scenario.to_string(),
                integrated,
                network_driver_cleanup,
                network_driver_cleanup_generation,
                smp_stress_run,
                smp_stress_run_generation,
                remote_preempt,
                remote_preempt_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                hart_count,
                cancelled_socket_waits: cancelled_socket_wait_count,
                revoked_packet_capabilities: revoked_packet_capability_count,
                invariant_checks,
                generation,
            },
        );
        self.integrated_smp_network_faults.push(IntegratedSmpNetworkFaultRecord {
            id: integrated,
            scenario: scenario.to_string(),
            network_driver_cleanup,
            network_driver_cleanup_generation,
            smp_stress_run,
            smp_stress_run_generation,
            remote_preempt,
            remote_preempt_generation,
            smp_cleanup_quiescence,
            smp_cleanup_quiescence_generation,
            driver_store,
            driver_store_generation,
            packet_device,
            packet_device_generation,
            adapter,
            adapter_generation,
            backend,
            io_cleanup,
            io_cleanup_generation,
            cancelled_socket_wait_count,
            cancelled_wait_token_count,
            revoked_packet_capability_count,
            hart_count,
            invariant_checks,
            generation,
            state: IntegratedSmpNetworkFaultState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn integrated_smp_network_faults(&self) -> &[IntegratedSmpNetworkFaultRecord] {
        &self.integrated_smp_network_faults
    }

    pub fn integrated_smp_network_fault_count(&self) -> usize {
        self.integrated_smp_network_faults.len()
    }

    pub fn check_integrated_smp_network_fault_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_smp_network_faults {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpNetworkFaultState::Recorded
                || record.network_driver_cleanup_generation == 0
                || record.smp_stress_run_generation == 0
                || record.remote_preempt_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.driver_store_generation == 0
                || record.packet_device_generation == 0
                || record.adapter_generation == 0
                || record.backend.generation == 0
                || record.io_cleanup_generation == 0
                || record.cancelled_socket_wait_count == 0
                || record.cancelled_wait_token_count == 0
                || record.revoked_packet_capability_count == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedSmpNetworkFaultInvalid {
                    integrated: record.id,
                });
            }
            for (label, id, generation, refs) in [
                (
                    "network-driver-cleanup",
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                    self.domains
                        .network
                        .network_driver_cleanups
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "smp-stress-run",
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    self.domains
                        .scheduler
                        .smp_stress_runs
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "remote-preempt",
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    self.domains
                        .scheduler
                        .remote_preempts
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "smp-cleanup-quiescence",
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    self.domains
                        .scheduler
                        .smp_cleanup_quiescence
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
            ] {
                if id == 0
                    || generation == 0
                    || !refs.into_iter().any(|item| item == (id, generation))
                {
                    return Err(SemanticInvariantError::IntegratedSmpNetworkFaultMissingEvidence {
                        integrated: record.id,
                        evidence: label,
                    });
                }
            }
            if self
                .validate_integrated_smp_network_fault(
                    u64::MAX,
                    &record.scenario,
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedSmpNetworkFaultInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedSmpNetworkFaultRecorded {
                            scenario,
                            integrated,
                            network_driver_cleanup,
                            network_driver_cleanup_generation,
                            smp_stress_run,
                            smp_stress_run_generation,
                            remote_preempt,
                            remote_preempt_generation,
                            smp_cleanup_quiescence,
                            smp_cleanup_quiescence_generation,
                            driver_store,
                            driver_store_generation,
                            packet_device,
                            packet_device_generation,
                            hart_count,
                            cancelled_socket_waits,
                            revoked_packet_capabilities,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *network_driver_cleanup == record.network_driver_cleanup
                            && *network_driver_cleanup_generation
                                == record.network_driver_cleanup_generation
                            && *smp_stress_run == record.smp_stress_run
                            && *smp_stress_run_generation == record.smp_stress_run_generation
                            && *remote_preempt == record.remote_preempt
                            && *remote_preempt_generation == record.remote_preempt_generation
                            && *smp_cleanup_quiescence == record.smp_cleanup_quiescence
                            && *smp_cleanup_quiescence_generation
                                == record.smp_cleanup_quiescence_generation
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *hart_count == record.hart_count
                            && *cancelled_socket_waits == record.cancelled_socket_wait_count
                            && *revoked_packet_capabilities
                                == record.revoked_packet_capability_count
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IntegratedSmpNetworkFaultMissingEvent {
                    integrated: record.id,
                });
            }
        }
        Ok(())
    }
}
