use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_display_scheduler_load(
        &self,
        integrated: IntegratedDisplaySchedulerLoadId,
        scenario: &str,
        framebuffer_benchmark: FramebufferBenchmarkId,
        framebuffer_benchmark_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated display/scheduler load id=0 is invalid");
        }
        if self
            .domains
            .integrated
            .integrated_display_scheduler_loads
            .iter()
            .any(|record| record.id == integrated)
        {
            return Err("integrated display/scheduler load evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated display/scheduler load scenario is empty");
        }
        if framebuffer_benchmark_generation == 0
            || scheduler_decision_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated display/scheduler load refs must carry generations");
        }

        let Some(benchmark) = self.domains.display.framebuffer_benchmarks.iter().find(|record| {
            record.id == framebuffer_benchmark
                && record.generation == framebuffer_benchmark_generation
        }) else {
            return Err("integrated display/scheduler load missing framebuffer benchmark evidence");
        };
        let Some(decision) = self.domains.scheduler.scheduler_decisions.iter().find(|record| {
            record.id == scheduler_decision && record.generation == scheduler_decision_generation
        }) else {
            return Err("integrated display/scheduler load missing scheduler decision evidence");
        };
        if benchmark.state != FramebufferBenchmarkState::Recorded
            || benchmark.sample_frames == 0
            || benchmark.sample_bytes == 0
            || benchmark.measured_nanos == 0
            || benchmark.measured_nanos > benchmark.budget_nanos
            || benchmark.throughput_bytes_per_sec == 0
            || benchmark.flushes_per_sec_milli == 0
            || benchmark.p99_latency_nanos == 0
        {
            return Err(
                "integrated display/scheduler load requires recorded framebuffer benchmark",
            );
        }
        if decision.state == SchedulerDecisionState::Dropped
            || decision.queue_generation == 0
            || decision.selected_activation_generation == 0
            || decision.owner_task_generation == 0
            || decision.decided_at_event == 0
        {
            return Err(
                "integrated display/scheduler load requires live scheduler decision evidence",
            );
        }
        if decision.decided_at_event > benchmark.recorded_at_event {
            return Err(
                "integrated display/scheduler load scheduler decision must precede display benchmark",
            );
        }
        if benchmark.owner_store_generation == 0
            || benchmark.display_generation == 0
            || benchmark.framebuffer_generation == 0
            || benchmark.display_capability_generation == 0
            || benchmark.framebuffer_write_generation == 0
            || benchmark.framebuffer_flush_region_generation == 0
            || benchmark.display_event_log_generation == 0
        {
            return Err("integrated display/scheduler load display refs must be generation exact");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_display_scheduler_load_with_id(
        &mut self,
        integrated: IntegratedDisplaySchedulerLoadId,
        scenario: &str,
        framebuffer_benchmark: FramebufferBenchmarkId,
        framebuffer_benchmark_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_display_scheduler_load(
                integrated,
                scenario,
                framebuffer_benchmark,
                framebuffer_benchmark_generation,
                scheduler_decision,
                scheduler_decision_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(benchmark) = self.domains.display.framebuffer_benchmarks.iter().find(|record| {
            record.id == framebuffer_benchmark
                && record.generation == framebuffer_benchmark_generation
        }) else {
            return false;
        };
        let Some(decision) = self.domains.scheduler.scheduler_decisions.iter().find(|record| {
            record.id == scheduler_decision && record.generation == scheduler_decision_generation
        }) else {
            return false;
        };
        let scheduler_load_units = 1;
        let generation = 1;
        self.domains.integrated.next_integrated_display_scheduler_load_id = self
            .domains
            .integrated
            .next_integrated_display_scheduler_load_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedDisplaySchedulerLoadRecorded {
                scenario: scenario.to_string(),
                integrated,
                framebuffer_benchmark,
                framebuffer_benchmark_generation,
                scheduler_decision,
                scheduler_decision_generation,
                owner_store: benchmark.owner_store,
                owner_store_generation: benchmark.owner_store_generation,
                queue: decision.queue,
                queue_generation: decision.queue_generation,
                selected_activation: decision.selected_activation,
                selected_activation_generation: decision.selected_activation_generation,
                display: benchmark.display,
                display_generation: benchmark.display_generation,
                framebuffer: benchmark.framebuffer,
                framebuffer_generation: benchmark.framebuffer_generation,
                sample_frames: benchmark.sample_frames,
                sample_bytes: benchmark.sample_bytes,
                scheduler_load_units,
                display_measured_nanos: benchmark.measured_nanos,
                invariant_checks,
                generation,
            },
        );
        self.domains.integrated.integrated_display_scheduler_loads.push(
            IntegratedDisplaySchedulerLoadRecord {
                id: integrated,
                scenario: scenario.to_string(),
                framebuffer_benchmark,
                framebuffer_benchmark_generation,
                scheduler_decision,
                scheduler_decision_generation,
                owner_store: benchmark.owner_store,
                owner_store_generation: benchmark.owner_store_generation,
                owner_task: decision.owner_task,
                owner_task_generation: decision.owner_task_generation,
                queue: decision.queue,
                queue_generation: decision.queue_generation,
                selected_activation: decision.selected_activation,
                selected_activation_generation: decision.selected_activation_generation,
                display: benchmark.display,
                display_generation: benchmark.display_generation,
                framebuffer: benchmark.framebuffer,
                framebuffer_generation: benchmark.framebuffer_generation,
                display_capability: benchmark.display_capability,
                display_capability_generation: benchmark.display_capability_generation,
                framebuffer_write: benchmark.framebuffer_write,
                framebuffer_write_generation: benchmark.framebuffer_write_generation,
                framebuffer_flush_region: benchmark.framebuffer_flush_region,
                framebuffer_flush_region_generation: benchmark.framebuffer_flush_region_generation,
                display_event_log: benchmark.display_event_log,
                display_event_log_generation: benchmark.display_event_log_generation,
                sample_frames: benchmark.sample_frames,
                sample_bytes: benchmark.sample_bytes,
                scheduler_load_units,
                display_measured_nanos: benchmark.measured_nanos,
                scheduler_decided_at_event: decision.decided_at_event,
                display_recorded_at_event: benchmark.recorded_at_event,
                invariant_checks,
                generation,
                state: IntegratedDisplaySchedulerLoadState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            },
        );
        true
    }

    pub fn integrated_display_scheduler_loads(&self) -> &[IntegratedDisplaySchedulerLoadRecord] {
        &self.domains.integrated.integrated_display_scheduler_loads
    }

    pub fn integrated_display_scheduler_load_count(&self) -> usize {
        self.domains.integrated.integrated_display_scheduler_loads.len()
    }

    pub fn check_integrated_display_scheduler_load_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.integrated.integrated_display_scheduler_loads {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplaySchedulerLoadState::Recorded
                || record.framebuffer_benchmark_generation == 0
                || record.scheduler_decision_generation == 0
                || record.owner_store_generation == 0
                || record.owner_task_generation == 0
                || record.queue_generation == 0
                || record.selected_activation_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.display_capability_generation == 0
                || record.framebuffer_write_generation == 0
                || record.framebuffer_flush_region_generation == 0
                || record.display_event_log_generation == 0
                || record.sample_frames == 0
                || record.sample_bytes == 0
                || record.scheduler_load_units == 0
                || record.display_measured_nanos == 0
                || record.scheduler_decided_at_event == 0
                || record.display_recorded_at_event == 0
                || record.scheduler_decided_at_event > record.display_recorded_at_event
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedDisplaySchedulerLoadInvalid {
                    integrated: record.id,
                });
            }
            for (label, id, generation, refs) in [
                (
                    "framebuffer-benchmark",
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                    self.domains
                        .display
                        .framebuffer_benchmarks
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "scheduler-decision",
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                    self.domains
                        .scheduler
                        .scheduler_decisions
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
                        SemanticInvariantError::IntegratedDisplaySchedulerLoadMissingEvidence {
                            integrated: record.id,
                            evidence: label,
                        },
                    );
                }
            }
            if self
                .validate_integrated_display_scheduler_load(
                    u64::MAX,
                    &record.scenario,
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedDisplaySchedulerLoadInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedDisplaySchedulerLoadRecorded {
                            scenario,
                            integrated,
                            framebuffer_benchmark,
                            framebuffer_benchmark_generation,
                            scheduler_decision,
                            scheduler_decision_generation,
                            owner_store,
                            owner_store_generation,
                            queue,
                            queue_generation,
                            selected_activation,
                            selected_activation_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            sample_frames,
                            sample_bytes,
                            scheduler_load_units,
                            display_measured_nanos,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *framebuffer_benchmark == record.framebuffer_benchmark
                            && *framebuffer_benchmark_generation
                                == record.framebuffer_benchmark_generation
                            && *scheduler_decision == record.scheduler_decision
                            && *scheduler_decision_generation
                                == record.scheduler_decision_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *queue == record.queue
                            && *queue_generation == record.queue_generation
                            && *selected_activation == record.selected_activation
                            && *selected_activation_generation
                                == record.selected_activation_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *sample_frames == record.sample_frames
                            && *sample_bytes == record.sample_bytes
                            && *scheduler_load_units == record.scheduler_load_units
                            && *display_measured_nanos == record.display_measured_nanos
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IntegratedDisplaySchedulerLoadMissingEvent {
                    integrated: record.id,
                });
            }
        }
        Ok(())
    }
}
