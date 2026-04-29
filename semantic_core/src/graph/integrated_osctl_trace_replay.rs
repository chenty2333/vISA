use super::*;

const X9_INTEGRATED_SCENARIO_COUNT: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IntegratedOsctlTraceReplayDerivedEvidence {
    contract_validation_ok: bool,
    replay_validation_ok: bool,
    graph_history_ok: bool,
    roots_match_counts: bool,
}

impl IntegratedOsctlTraceReplayDerivedEvidence {
    const fn complete(self) -> bool {
        self.contract_validation_ok
            && self.replay_validation_ok
            && self.graph_history_ok
            && self.roots_match_counts
    }
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_osctl_trace_replay(
        &self,
        integrated: IntegratedOsctlTraceReplayId,
        scenario: &str,
        integrated_smp_preemption_cleanup: IntegratedSmpPreemptionCleanupId,
        integrated_smp_preemption_cleanup_generation: Generation,
        integrated_smp_network_fault: IntegratedSmpNetworkFaultId,
        integrated_smp_network_fault_generation: Generation,
        integrated_disk_preempt_fault: IntegratedDiskPreemptFaultId,
        integrated_disk_preempt_fault_generation: Generation,
        integrated_simd_migration: IntegratedSimdMigrationId,
        integrated_simd_migration_generation: Generation,
        integrated_network_disk_io: IntegratedNetworkDiskIoId,
        integrated_network_disk_io_generation: Generation,
        integrated_display_scheduler_load: IntegratedDisplaySchedulerLoadId,
        integrated_display_scheduler_load_generation: Generation,
        integrated_snapshot_io_lease_barrier: IntegratedSnapshotIoLeaseBarrierId,
        integrated_snapshot_io_lease_barrier_generation: Generation,
        integrated_code_publish_smp_workload: IntegratedCodePublishSmpWorkloadId,
        integrated_code_publish_smp_workload_generation: Generation,
        integrated_display_panic: IntegratedDisplayPanicId,
        integrated_display_panic_generation: Generation,
        replay_event_cursor: EventId,
        stable_view_count: u32,
        historical_edge_count: u32,
        replayed_root_count: u32,
        integrated_scenario_count: u32,
        golden_trace_count: u32,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        self.validate_integrated_osctl_trace_replay_candidate(
            integrated,
            scenario,
            integrated_smp_preemption_cleanup,
            integrated_smp_preemption_cleanup_generation,
            integrated_smp_network_fault,
            integrated_smp_network_fault_generation,
            integrated_disk_preempt_fault,
            integrated_disk_preempt_fault_generation,
            integrated_simd_migration,
            integrated_simd_migration_generation,
            integrated_network_disk_io,
            integrated_network_disk_io_generation,
            integrated_display_scheduler_load,
            integrated_display_scheduler_load_generation,
            integrated_snapshot_io_lease_barrier,
            integrated_snapshot_io_lease_barrier_generation,
            integrated_code_publish_smp_workload,
            integrated_code_publish_smp_workload_generation,
            integrated_display_panic,
            integrated_display_panic_generation,
            replay_event_cursor,
            stable_view_count,
            historical_edge_count,
            replayed_root_count,
            integrated_scenario_count,
            golden_trace_count,
            invariant_checks,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_integrated_osctl_trace_replay_candidate(
        &self,
        integrated: IntegratedOsctlTraceReplayId,
        scenario: &str,
        integrated_smp_preemption_cleanup: IntegratedSmpPreemptionCleanupId,
        integrated_smp_preemption_cleanup_generation: Generation,
        integrated_smp_network_fault: IntegratedSmpNetworkFaultId,
        integrated_smp_network_fault_generation: Generation,
        integrated_disk_preempt_fault: IntegratedDiskPreemptFaultId,
        integrated_disk_preempt_fault_generation: Generation,
        integrated_simd_migration: IntegratedSimdMigrationId,
        integrated_simd_migration_generation: Generation,
        integrated_network_disk_io: IntegratedNetworkDiskIoId,
        integrated_network_disk_io_generation: Generation,
        integrated_display_scheduler_load: IntegratedDisplaySchedulerLoadId,
        integrated_display_scheduler_load_generation: Generation,
        integrated_snapshot_io_lease_barrier: IntegratedSnapshotIoLeaseBarrierId,
        integrated_snapshot_io_lease_barrier_generation: Generation,
        integrated_code_publish_smp_workload: IntegratedCodePublishSmpWorkloadId,
        integrated_code_publish_smp_workload_generation: Generation,
        integrated_display_panic: IntegratedDisplayPanicId,
        integrated_display_panic_generation: Generation,
        replay_event_cursor: EventId,
        stable_view_count: u32,
        historical_edge_count: u32,
        replayed_root_count: u32,
        integrated_scenario_count: u32,
        golden_trace_count: u32,
        invariant_checks: u32,
        allow_existing_integrated: Option<IntegratedOsctlTraceReplayId>,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated osctl trace replay id=0 is invalid");
        }
        if self
            .integrated_osctl_trace_replays
            .iter()
            .any(|record| record.id == integrated && Some(record.id) != allow_existing_integrated)
        {
            return Err("integrated osctl trace replay evidence already exists");
        }
        if scenario.is_empty() || replay_event_cursor == 0 || invariant_checks == 0 {
            return Err("integrated osctl trace replay requires scenario, cursor, and invariants");
        }
        if integrated_scenario_count != X9_INTEGRATED_SCENARIO_COUNT
            || stable_view_count < X9_INTEGRATED_SCENARIO_COUNT
            || historical_edge_count < X9_INTEGRATED_SCENARIO_COUNT
            || replayed_root_count < X9_INTEGRATED_SCENARIO_COUNT
            || golden_trace_count < X9_INTEGRATED_SCENARIO_COUNT
        {
            return Err("integrated osctl trace replay requires complete stable evidence");
        }

        let source_events = [
            self.integrated_smp_preemption_cleanups
                .iter()
                .find(|record| {
                    record.id == integrated_smp_preemption_cleanup
                        && record.generation == integrated_smp_preemption_cleanup_generation
                        && record.state == IntegratedSmpPreemptionCleanupState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_smp_network_faults
                .iter()
                .find(|record| {
                    record.id == integrated_smp_network_fault
                        && record.generation == integrated_smp_network_fault_generation
                        && record.state == IntegratedSmpNetworkFaultState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_disk_preempt_faults
                .iter()
                .find(|record| {
                    record.id == integrated_disk_preempt_fault
                        && record.generation == integrated_disk_preempt_fault_generation
                        && record.state == IntegratedDiskPreemptFaultState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_simd_migrations
                .iter()
                .find(|record| {
                    record.id == integrated_simd_migration
                        && record.generation == integrated_simd_migration_generation
                        && record.state == IntegratedSimdMigrationState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_network_disk_ios
                .iter()
                .find(|record| {
                    record.id == integrated_network_disk_io
                        && record.generation == integrated_network_disk_io_generation
                        && record.state == IntegratedNetworkDiskIoState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_display_scheduler_loads
                .iter()
                .find(|record| {
                    record.id == integrated_display_scheduler_load
                        && record.generation == integrated_display_scheduler_load_generation
                        && record.state == IntegratedDisplaySchedulerLoadState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| {
                    record.id == integrated_snapshot_io_lease_barrier
                        && record.generation == integrated_snapshot_io_lease_barrier_generation
                        && record.state == IntegratedSnapshotIoLeaseBarrierState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_code_publish_smp_workloads
                .iter()
                .find(|record| {
                    record.id == integrated_code_publish_smp_workload
                        && record.generation == integrated_code_publish_smp_workload_generation
                        && record.state == IntegratedCodePublishSmpWorkloadState::Recorded
                })
                .map(|record| record.recorded_at_event),
            self.integrated_display_panics
                .iter()
                .find(|record| {
                    record.id == integrated_display_panic
                        && record.generation == integrated_display_panic_generation
                        && record.state == IntegratedDisplayPanicState::Recorded
                })
                .map(|record| record.recorded_at_event),
        ];
        if source_events.iter().any(Option::is_none) {
            return Err("integrated osctl trace replay missing integrated scenario evidence");
        }
        let max_source_event = source_events
            .iter()
            .filter_map(|event| *event)
            .max()
            .unwrap_or(0);
        if replay_event_cursor < max_source_event || replay_event_cursor > self.event_log.cursor() {
            return Err("integrated osctl trace replay cursor does not cover source evidence");
        }
        if !self
            .derive_integrated_osctl_trace_replay_evidence(
                replay_event_cursor,
                stable_view_count,
                historical_edge_count,
                replayed_root_count,
                integrated_scenario_count,
                golden_trace_count,
                max_source_event,
            )
            .complete()
        {
            return Err("integrated osctl trace replay derived validation failed");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_integrated_osctl_trace_replay_evidence(
        &self,
        replay_event_cursor: EventId,
        stable_view_count: u32,
        historical_edge_count: u32,
        replayed_root_count: u32,
        integrated_scenario_count: u32,
        golden_trace_count: u32,
        max_source_event: EventId,
    ) -> IntegratedOsctlTraceReplayDerivedEvidence {
        let roots_match_counts = integrated_scenario_count == X9_INTEGRATED_SCENARIO_COUNT
            && stable_view_count >= integrated_scenario_count
            && historical_edge_count >= integrated_scenario_count
            && replayed_root_count >= integrated_scenario_count
            && golden_trace_count >= integrated_scenario_count;
        let graph_history_ok = historical_edge_count >= X9_INTEGRATED_SCENARIO_COUNT
            && replay_event_cursor >= max_source_event;
        let replay_validation_ok = replay_event_cursor >= max_source_event
            && replay_event_cursor <= self.event_log.cursor();
        let contract_validation_ok = roots_match_counts && graph_history_ok && replay_validation_ok;
        IntegratedOsctlTraceReplayDerivedEvidence {
            contract_validation_ok,
            replay_validation_ok,
            graph_history_ok,
            roots_match_counts,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_osctl_trace_replay_with_id(
        &mut self,
        integrated: IntegratedOsctlTraceReplayId,
        scenario: &str,
        integrated_smp_preemption_cleanup: IntegratedSmpPreemptionCleanupId,
        integrated_smp_preemption_cleanup_generation: Generation,
        integrated_smp_network_fault: IntegratedSmpNetworkFaultId,
        integrated_smp_network_fault_generation: Generation,
        integrated_disk_preempt_fault: IntegratedDiskPreemptFaultId,
        integrated_disk_preempt_fault_generation: Generation,
        integrated_simd_migration: IntegratedSimdMigrationId,
        integrated_simd_migration_generation: Generation,
        integrated_network_disk_io: IntegratedNetworkDiskIoId,
        integrated_network_disk_io_generation: Generation,
        integrated_display_scheduler_load: IntegratedDisplaySchedulerLoadId,
        integrated_display_scheduler_load_generation: Generation,
        integrated_snapshot_io_lease_barrier: IntegratedSnapshotIoLeaseBarrierId,
        integrated_snapshot_io_lease_barrier_generation: Generation,
        integrated_code_publish_smp_workload: IntegratedCodePublishSmpWorkloadId,
        integrated_code_publish_smp_workload_generation: Generation,
        integrated_display_panic: IntegratedDisplayPanicId,
        integrated_display_panic_generation: Generation,
        replay_event_cursor: EventId,
        stable_view_count: u32,
        historical_edge_count: u32,
        replayed_root_count: u32,
        integrated_scenario_count: u32,
        golden_trace_count: u32,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_osctl_trace_replay(
                integrated,
                scenario,
                integrated_smp_preemption_cleanup,
                integrated_smp_preemption_cleanup_generation,
                integrated_smp_network_fault,
                integrated_smp_network_fault_generation,
                integrated_disk_preempt_fault,
                integrated_disk_preempt_fault_generation,
                integrated_simd_migration,
                integrated_simd_migration_generation,
                integrated_network_disk_io,
                integrated_network_disk_io_generation,
                integrated_display_scheduler_load,
                integrated_display_scheduler_load_generation,
                integrated_snapshot_io_lease_barrier,
                integrated_snapshot_io_lease_barrier_generation,
                integrated_code_publish_smp_workload,
                integrated_code_publish_smp_workload_generation,
                integrated_display_panic,
                integrated_display_panic_generation,
                replay_event_cursor,
                stable_view_count,
                historical_edge_count,
                replayed_root_count,
                integrated_scenario_count,
                golden_trace_count,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }
        let max_source_event = [
            self.integrated_smp_preemption_cleanups
                .iter()
                .find(|record| {
                    record.id == integrated_smp_preemption_cleanup
                        && record.generation == integrated_smp_preemption_cleanup_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_smp_network_faults
                .iter()
                .find(|record| {
                    record.id == integrated_smp_network_fault
                        && record.generation == integrated_smp_network_fault_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_disk_preempt_faults
                .iter()
                .find(|record| {
                    record.id == integrated_disk_preempt_fault
                        && record.generation == integrated_disk_preempt_fault_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_simd_migrations
                .iter()
                .find(|record| {
                    record.id == integrated_simd_migration
                        && record.generation == integrated_simd_migration_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_network_disk_ios
                .iter()
                .find(|record| {
                    record.id == integrated_network_disk_io
                        && record.generation == integrated_network_disk_io_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_display_scheduler_loads
                .iter()
                .find(|record| {
                    record.id == integrated_display_scheduler_load
                        && record.generation == integrated_display_scheduler_load_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| {
                    record.id == integrated_snapshot_io_lease_barrier
                        && record.generation == integrated_snapshot_io_lease_barrier_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_code_publish_smp_workloads
                .iter()
                .find(|record| {
                    record.id == integrated_code_publish_smp_workload
                        && record.generation == integrated_code_publish_smp_workload_generation
                })
                .map(|record| record.recorded_at_event),
            self.integrated_display_panics
                .iter()
                .find(|record| {
                    record.id == integrated_display_panic
                        && record.generation == integrated_display_panic_generation
                })
                .map(|record| record.recorded_at_event),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);
        let derived = self.derive_integrated_osctl_trace_replay_evidence(
            replay_event_cursor,
            stable_view_count,
            historical_edge_count,
            replayed_root_count,
            integrated_scenario_count,
            golden_trace_count,
            max_source_event,
        );
        let generation = 1;
        self.next_integrated_osctl_trace_replay_id = self
            .next_integrated_osctl_trace_replay_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedOsctlTraceReplayRecorded {
                scenario: scenario.to_string(),
                integrated,
                replay_event_cursor,
                integrated_scenario_count,
                replayed_root_count,
                stable_view_count,
                historical_edge_count,
                golden_trace_count,
                contract_validation_ok: derived.contract_validation_ok,
                replay_validation_ok: derived.replay_validation_ok,
                graph_history_ok: derived.graph_history_ok,
                roots_match_counts: derived.roots_match_counts,
                invariant_checks,
                generation,
            },
        );
        self.integrated_osctl_trace_replays
            .push(IntegratedOsctlTraceReplayRecord {
                id: integrated,
                scenario: scenario.to_string(),
                integrated_smp_preemption_cleanup,
                integrated_smp_preemption_cleanup_generation,
                integrated_smp_network_fault,
                integrated_smp_network_fault_generation,
                integrated_disk_preempt_fault,
                integrated_disk_preempt_fault_generation,
                integrated_simd_migration,
                integrated_simd_migration_generation,
                integrated_network_disk_io,
                integrated_network_disk_io_generation,
                integrated_display_scheduler_load,
                integrated_display_scheduler_load_generation,
                integrated_snapshot_io_lease_barrier,
                integrated_snapshot_io_lease_barrier_generation,
                integrated_code_publish_smp_workload,
                integrated_code_publish_smp_workload_generation,
                integrated_display_panic,
                integrated_display_panic_generation,
                replay_event_cursor,
                stable_view_count,
                historical_edge_count,
                replayed_root_count,
                integrated_scenario_count,
                golden_trace_count,
                contract_validation_ok: derived.contract_validation_ok,
                replay_validation_ok: derived.replay_validation_ok,
                graph_history_ok: derived.graph_history_ok,
                roots_match_counts: derived.roots_match_counts,
                invariant_checks,
                generation,
                state: IntegratedOsctlTraceReplayState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn integrated_osctl_trace_replays(&self) -> &[IntegratedOsctlTraceReplayRecord] {
        &self.integrated_osctl_trace_replays
    }

    pub fn integrated_osctl_trace_replay_count(&self) -> usize {
        self.integrated_osctl_trace_replays.len()
    }

    pub fn check_integrated_osctl_trace_replay_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_osctl_trace_replays {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedOsctlTraceReplayState::Recorded
                || record.replay_event_cursor == 0
                || record.integrated_scenario_count != X9_INTEGRATED_SCENARIO_COUNT
                || record.stable_view_count < X9_INTEGRATED_SCENARIO_COUNT
                || record.historical_edge_count < X9_INTEGRATED_SCENARIO_COUNT
                || record.replayed_root_count < X9_INTEGRATED_SCENARIO_COUNT
                || record.golden_trace_count < X9_INTEGRATED_SCENARIO_COUNT
                || !record.contract_validation_ok
                || !record.replay_validation_ok
                || !record.graph_history_ok
                || !record.roots_match_counts
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                return Err(SemanticInvariantError::IntegratedOsctlTraceReplayInvalid {
                    integrated: record.id,
                });
            }
            if self
                .validate_integrated_osctl_trace_replay_candidate(
                    record.id,
                    &record.scenario,
                    record.integrated_smp_preemption_cleanup,
                    record.integrated_smp_preemption_cleanup_generation,
                    record.integrated_smp_network_fault,
                    record.integrated_smp_network_fault_generation,
                    record.integrated_disk_preempt_fault,
                    record.integrated_disk_preempt_fault_generation,
                    record.integrated_simd_migration,
                    record.integrated_simd_migration_generation,
                    record.integrated_network_disk_io,
                    record.integrated_network_disk_io_generation,
                    record.integrated_display_scheduler_load,
                    record.integrated_display_scheduler_load_generation,
                    record.integrated_snapshot_io_lease_barrier,
                    record.integrated_snapshot_io_lease_barrier_generation,
                    record.integrated_code_publish_smp_workload,
                    record.integrated_code_publish_smp_workload_generation,
                    record.integrated_display_panic,
                    record.integrated_display_panic_generation,
                    record.replay_event_cursor,
                    record.stable_view_count,
                    record.historical_edge_count,
                    record.replayed_root_count,
                    record.integrated_scenario_count,
                    record.golden_trace_count,
                    record.invariant_checks,
                    Some(record.id),
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedOsctlTraceReplayInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedOsctlTraceReplayRecorded {
                            scenario,
                            integrated,
                            replay_event_cursor,
                            integrated_scenario_count,
                            replayed_root_count,
                            stable_view_count,
                            historical_edge_count,
                            golden_trace_count,
                            contract_validation_ok,
                            replay_validation_ok,
                            graph_history_ok,
                            roots_match_counts,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *replay_event_cursor == record.replay_event_cursor
                            && *integrated_scenario_count == record.integrated_scenario_count
                            && *replayed_root_count == record.replayed_root_count
                            && *stable_view_count == record.stable_view_count
                            && *historical_edge_count == record.historical_edge_count
                            && *golden_trace_count == record.golden_trace_count
                            && *contract_validation_ok == record.contract_validation_ok
                            && *replay_validation_ok == record.replay_validation_ok
                            && *graph_history_ok == record.graph_history_ok
                            && *roots_match_counts == record.roots_match_counts
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::IntegratedOsctlTraceReplayMissingEvent {
                        integrated: record.id,
                    },
                );
            }
        }
        Ok(())
    }
}
