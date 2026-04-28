use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_code_publish_smp_workload(
        &self,
        integrated: IntegratedCodePublishSmpWorkloadId,
        scenario: &str,
        smp_stress_run: SmpStressRunId,
        smp_stress_run_generation: Generation,
        smp_code_publish_barrier: SmpCodePublishBarrierId,
        smp_code_publish_barrier_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        self.validate_integrated_code_publish_smp_workload_candidate(
            integrated,
            scenario,
            smp_stress_run,
            smp_stress_run_generation,
            smp_code_publish_barrier,
            smp_code_publish_barrier_generation,
            invariant_checks,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_integrated_code_publish_smp_workload_candidate(
        &self,
        integrated: IntegratedCodePublishSmpWorkloadId,
        scenario: &str,
        smp_stress_run: SmpStressRunId,
        smp_stress_run_generation: Generation,
        smp_code_publish_barrier: SmpCodePublishBarrierId,
        smp_code_publish_barrier_generation: Generation,
        invariant_checks: u32,
        allow_existing_integrated: Option<IntegratedCodePublishSmpWorkloadId>,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated code-publish/SMP workload id=0 is invalid");
        }
        if self
            .integrated_code_publish_smp_workloads
            .iter()
            .any(|record| record.id == integrated && Some(record.id) != allow_existing_integrated)
        {
            return Err("integrated code-publish/SMP workload evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated code-publish/SMP workload scenario is empty");
        }
        if smp_stress_run_generation == 0
            || smp_code_publish_barrier_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated code-publish/SMP workload refs must carry generations");
        }

        let Some(stress) = self.smp_stress_runs.iter().find(|record| {
            record.id == smp_stress_run && record.generation == smp_stress_run_generation
        }) else {
            return Err("integrated code-publish/SMP workload missing stress evidence");
        };
        let Some(barrier) = self.smp_code_publish_barriers.iter().find(|record| {
            record.id == smp_code_publish_barrier
                && record.generation == smp_code_publish_barrier_generation
        }) else {
            return Err("integrated code-publish/SMP workload missing code publish barrier");
        };
        let Some(rendezvous) = self.stop_the_world_rendezvous.iter().find(|record| {
            record.id == barrier.rendezvous && record.generation == barrier.rendezvous_generation
        }) else {
            return Err("integrated code-publish/SMP workload missing publish rendezvous");
        };
        let Some(safe_point) = self.smp_safe_points.iter().find(|record| {
            record.id == rendezvous.safe_point
                && record.generation == rendezvous.safe_point_generation
        }) else {
            return Err("integrated code-publish/SMP workload missing publish safe point");
        };

        if stress.state != SmpStressRunState::Recorded
            || stress.property_failures != 0
            || stress.hart_count < 2
            || stress.iterations < 3
            || stress.observed_safe_point_count == 0
            || stress.observed_rendezvous_count == 0
            || stress.observed_code_publish_barrier_count == 0
            || stress.last_code_publish_barrier != barrier.id
            || stress.last_code_publish_barrier_generation != barrier.generation
            || stress.invariant_checks > invariant_checks
        {
            return Err("integrated code-publish/SMP workload requires clean stress evidence");
        }
        if barrier.state != SmpCodePublishBarrierState::Validated
            || !barrier.remote_icache_sync_required
            || barrier.code_publish_executed
            || barrier.code_publish_epoch_after != barrier.code_publish_epoch_before + 1
            || barrier.participants.len() < 2
            || barrier
                .participants
                .iter()
                .any(|participant| !participant.semantic_icache_sync)
            || rendezvous.state != StopTheWorldRendezvousState::Completed
            || !rendezvous.stop_new_activations
            || rendezvous.participants.len() < 2
            || safe_point.state != SmpSafePointState::Recorded
        {
            return Err(
                "integrated code-publish/SMP workload requires semantic code publish barrier",
            );
        }
        if stress.event_log_cursor < barrier.validated_at_event
            || stress.recorded_at_event <= barrier.validated_at_event
        {
            return Err("integrated code-publish/SMP workload stress must observe publish barrier");
        }

        Ok(())
    }

    pub fn record_integrated_code_publish_smp_workload_with_id(
        &mut self,
        integrated: IntegratedCodePublishSmpWorkloadId,
        scenario: &str,
        smp_stress_run: SmpStressRunId,
        smp_stress_run_generation: Generation,
        smp_code_publish_barrier: SmpCodePublishBarrierId,
        smp_code_publish_barrier_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_code_publish_smp_workload(
                integrated,
                scenario,
                smp_stress_run,
                smp_stress_run_generation,
                smp_code_publish_barrier,
                smp_code_publish_barrier_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(stress) = self.smp_stress_runs.iter().find(|record| {
            record.id == smp_stress_run && record.generation == smp_stress_run_generation
        }) else {
            return false;
        };
        let Some(barrier) = self.smp_code_publish_barriers.iter().find(|record| {
            record.id == smp_code_publish_barrier
                && record.generation == smp_code_publish_barrier_generation
        }) else {
            return false;
        };
        let Some(rendezvous) = self.stop_the_world_rendezvous.iter().find(|record| {
            record.id == barrier.rendezvous && record.generation == barrier.rendezvous_generation
        }) else {
            return false;
        };

        let publish_rendezvous = rendezvous.id;
        let publish_rendezvous_generation = rendezvous.generation;
        let publish_safe_point = rendezvous.safe_point;
        let publish_safe_point_generation = rendezvous.safe_point_generation;
        let hart_count = stress.hart_count;
        let workload_iterations = stress.iterations;
        let observed_safe_point_count = stress.observed_safe_point_count;
        let observed_rendezvous_count = stress.observed_rendezvous_count;
        let observed_code_publish_barrier_count = stress.observed_code_publish_barrier_count;
        let code_publish_epoch_before = barrier.code_publish_epoch_before;
        let code_publish_epoch_after = barrier.code_publish_epoch_after;
        let remote_icache_sync_required = barrier.remote_icache_sync_required;
        let code_publish_executed = barrier.code_publish_executed;
        let participant_count = barrier.participants.len() as u32;
        let stress_event_log_cursor = stress.event_log_cursor;
        let barrier_event = barrier.validated_at_event;
        let stress_recorded_at_event = stress.recorded_at_event;
        let generation = 1;

        self.next_integrated_code_publish_smp_workload_id = self
            .next_integrated_code_publish_smp_workload_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedCodePublishSmpWorkloadRecorded {
                scenario: scenario.to_string(),
                integrated,
                smp_stress_run,
                smp_stress_run_generation,
                smp_code_publish_barrier,
                smp_code_publish_barrier_generation,
                publish_rendezvous,
                publish_rendezvous_generation,
                publish_safe_point,
                publish_safe_point_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                hart_count,
                workload_iterations,
                invariant_checks,
                generation,
            },
        );
        self.integrated_code_publish_smp_workloads
            .push(IntegratedCodePublishSmpWorkloadRecord {
                id: integrated,
                scenario: scenario.to_string(),
                smp_stress_run,
                smp_stress_run_generation,
                smp_code_publish_barrier,
                smp_code_publish_barrier_generation,
                publish_rendezvous,
                publish_rendezvous_generation,
                publish_safe_point,
                publish_safe_point_generation,
                hart_count,
                workload_iterations,
                observed_safe_point_count,
                observed_rendezvous_count,
                observed_code_publish_barrier_count,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                participant_count,
                stress_event_log_cursor,
                barrier_event,
                stress_recorded_at_event,
                invariant_checks,
                generation,
                state: IntegratedCodePublishSmpWorkloadState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn integrated_code_publish_smp_workloads(
        &self,
    ) -> &[IntegratedCodePublishSmpWorkloadRecord] {
        &self.integrated_code_publish_smp_workloads
    }

    pub fn integrated_code_publish_smp_workload_count(&self) -> usize {
        self.integrated_code_publish_smp_workloads.len()
    }

    pub fn check_integrated_code_publish_smp_workload_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_code_publish_smp_workloads {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedCodePublishSmpWorkloadState::Recorded
                || record.smp_stress_run_generation == 0
                || record.smp_code_publish_barrier_generation == 0
                || record.publish_rendezvous_generation == 0
                || record.publish_safe_point_generation == 0
                || record.hart_count < 2
                || record.workload_iterations < 3
                || record.observed_safe_point_count == 0
                || record.observed_rendezvous_count == 0
                || record.observed_code_publish_barrier_count == 0
                || record.code_publish_epoch_after != record.code_publish_epoch_before + 1
                || !record.remote_icache_sync_required
                || record.code_publish_executed
                || record.participant_count < 2
                || record.stress_event_log_cursor < record.barrier_event
                || record.stress_recorded_at_event <= record.barrier_event
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                return Err(
                    SemanticInvariantError::IntegratedCodePublishSmpWorkloadInvalid {
                        integrated: record.id,
                    },
                );
            }
            for (label, id, generation, refs) in [
                (
                    "smp-stress-run",
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    self.smp_stress_runs
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "smp-code-publish-barrier",
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                    self.smp_code_publish_barriers
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "stop-the-world-rendezvous",
                    record.publish_rendezvous,
                    record.publish_rendezvous_generation,
                    self.stop_the_world_rendezvous
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "smp-safe-point",
                    record.publish_safe_point,
                    record.publish_safe_point_generation,
                    self.smp_safe_points
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
            ] {
                if id == 0
                    || generation == 0
                    || !refs.into_iter().any(|item| item == (id, generation))
                {
                    return Err(
                        SemanticInvariantError::IntegratedCodePublishSmpWorkloadMissingEvidence {
                            integrated: record.id,
                            evidence: label,
                        },
                    );
                }
            }
            if self
                .validate_integrated_code_publish_smp_workload_candidate(
                    record.id,
                    &record.scenario,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                    record.invariant_checks,
                    Some(record.id),
                )
                .is_err()
            {
                return Err(
                    SemanticInvariantError::IntegratedCodePublishSmpWorkloadInvalid {
                        integrated: record.id,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedCodePublishSmpWorkloadRecorded {
                            scenario,
                            integrated,
                            smp_stress_run,
                            smp_stress_run_generation,
                            smp_code_publish_barrier,
                            smp_code_publish_barrier_generation,
                            publish_rendezvous,
                            publish_rendezvous_generation,
                            publish_safe_point,
                            publish_safe_point_generation,
                            code_publish_epoch_before,
                            code_publish_epoch_after,
                            hart_count,
                            workload_iterations,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *smp_stress_run == record.smp_stress_run
                            && *smp_stress_run_generation
                                == record.smp_stress_run_generation
                            && *smp_code_publish_barrier
                                == record.smp_code_publish_barrier
                            && *smp_code_publish_barrier_generation
                                == record.smp_code_publish_barrier_generation
                            && *publish_rendezvous == record.publish_rendezvous
                            && *publish_rendezvous_generation
                                == record.publish_rendezvous_generation
                            && *publish_safe_point == record.publish_safe_point
                            && *publish_safe_point_generation
                                == record.publish_safe_point_generation
                            && *code_publish_epoch_before
                                == record.code_publish_epoch_before
                            && *code_publish_epoch_after == record.code_publish_epoch_after
                            && *hart_count == record.hart_count
                            && *workload_iterations == record.workload_iterations
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::IntegratedCodePublishSmpWorkloadMissingEvent {
                        integrated: record.id,
                    },
                );
            }
        }
        Ok(())
    }
}
