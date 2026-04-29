use super::*;

impl SemanticGraph {
    pub(crate) fn validate_smp_scaling_benchmark(
        &self,
        benchmark: SmpScalingBenchmarkId,
        scenario: &str,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        workload_units: u64,
        baseline_single_hart_nanos: u64,
        measured_smp_nanos: u64,
        budget_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("smp scaling benchmark id=0 is invalid");
        }
        if self.smp_scaling_benchmarks.iter().any(|record| record.id == benchmark) {
            return Err("smp scaling benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("smp scaling benchmark scenario is empty");
        }
        let Some(stress) = self
            .smp_stress_runs
            .iter()
            .find(|record| record.id == stress_run && record.generation == stress_run_generation)
        else {
            return Err("smp scaling benchmark missing stress run evidence");
        };
        if stress.state != SmpStressRunState::Recorded || stress.property_failures != 0 {
            return Err("smp scaling benchmark requires clean stress evidence");
        }
        if stress.hart_count < 2 {
            return Err("smp scaling benchmark requires at least two harts");
        }
        let minimum_workload = stress.iterations as u64 * stress.hart_count as u64;
        if workload_units < minimum_workload {
            return Err("smp scaling benchmark workload is too small");
        }
        if baseline_single_hart_nanos == 0 {
            return Err("smp scaling benchmark baseline nanos must be nonzero");
        }
        if measured_smp_nanos == 0 {
            return Err("smp scaling benchmark measured nanos must be nonzero");
        }
        if budget_nanos == 0 {
            return Err("smp scaling benchmark budget nanos must be nonzero");
        }
        if measured_smp_nanos > budget_nanos {
            return Err("smp scaling benchmark exceeds budget");
        }
        if measured_smp_nanos >= baseline_single_hart_nanos {
            return Err("smp scaling benchmark must improve over single-hart baseline");
        }
        let Some(speedup_milli) =
            Self::derive_scaling_speedup_milli(baseline_single_hart_nanos, measured_smp_nanos)
        else {
            return Err("smp scaling benchmark speedup overflow");
        };
        let efficiency_milli = speedup_milli / stress.hart_count as u64;
        if speedup_milli < 1_000 || efficiency_milli == 0 || efficiency_milli > 1_000 {
            return Err("smp scaling benchmark efficiency is outside harness bounds");
        }
        if self.check_invariants().is_err() {
            return Err("smp scaling benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_smp_scaling_benchmark_with_id(
        &mut self,
        benchmark: SmpScalingBenchmarkId,
        scenario: &str,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        workload_units: u64,
        baseline_single_hart_nanos: u64,
        measured_smp_nanos: u64,
        budget_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_scaling_benchmark(
                benchmark,
                scenario,
                stress_run,
                stress_run_generation,
                workload_units,
                baseline_single_hart_nanos,
                measured_smp_nanos,
                budget_nanos,
            )
            .is_err()
        {
            return false;
        }
        let Some(stress) = self
            .smp_stress_runs
            .iter()
            .find(|record| record.id == stress_run && record.generation == stress_run_generation)
        else {
            return false;
        };
        let hart_count = stress.hart_count;
        let stress_safe_point_count = stress.observed_safe_point_count;
        let stress_rendezvous_count = stress.observed_rendezvous_count;
        let stress_property_failures = stress.property_failures;
        let Some(speedup_milli) =
            Self::derive_scaling_speedup_milli(baseline_single_hart_nanos, measured_smp_nanos)
        else {
            return false;
        };
        let efficiency_milli = speedup_milli / hart_count as u64;
        let event_log_cursor = self.event_log.cursor();
        let generation = 1;
        self.next_smp_scaling_benchmark_id = self.next_smp_scaling_benchmark_id.max(benchmark + 1);
        let recorded_at_event = self.event_log.push(
            "scheduler",
            EventKind::SmpScalingBenchmarkRecorded {
                benchmark,
                stress_run,
                stress_run_generation,
                hart_count,
                workload_units,
                measured_smp_nanos,
                budget_nanos,
                speedup_milli,
                efficiency_milli,
                generation,
            },
        );
        self.smp_scaling_benchmarks.push(SmpScalingBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
            stress_run,
            stress_run_generation,
            hart_count,
            workload_units,
            baseline_single_hart_nanos,
            measured_smp_nanos,
            budget_nanos,
            speedup_milli,
            efficiency_milli,
            event_log_cursor,
            stress_safe_point_count,
            stress_rendezvous_count,
            stress_property_failures,
            generation,
            state: SmpScalingBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn smp_scaling_benchmarks(&self) -> &[SmpScalingBenchmarkRecord] {
        &self.smp_scaling_benchmarks
    }

    pub fn smp_scaling_benchmark_count(&self) -> usize {
        self.smp_scaling_benchmarks.len()
    }

    pub fn check_smp_scaling_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.smp_scaling_benchmarks {
            let Some(stress) = self.smp_stress_runs.iter().find(|stress| {
                stress.id == record.stress_run && stress.generation == record.stress_run_generation
            }) else {
                return Err(SemanticInvariantError::SmpScalingBenchmarkMissingStressRun {
                    benchmark: record.id,
                    stress_run: record.stress_run,
                });
            };
            let minimum_workload = stress.iterations as u64 * stress.hart_count as u64;
            let speedup_milli = Self::derive_scaling_speedup_milli(
                record.baseline_single_hart_nanos,
                record.measured_smp_nanos,
            );
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.stress_run_generation == 0
                || record.hart_count != stress.hart_count
                || record.hart_count < 2
                || record.workload_units < minimum_workload
                || record.baseline_single_hart_nanos == 0
                || record.measured_smp_nanos == 0
                || record.budget_nanos == 0
                || record.measured_smp_nanos > record.budget_nanos
                || record.measured_smp_nanos >= record.baseline_single_hart_nanos
                || speedup_milli != Some(record.speedup_milli)
                || record.efficiency_milli != record.speedup_milli / record.hart_count as u64
                || record.speedup_milli < 1_000
                || record.efficiency_milli == 0
                || record.efficiency_milli > 1_000
                || record.event_log_cursor == 0
                || record.event_log_cursor >= record.recorded_at_event
                || record.state != SmpScalingBenchmarkState::Recorded
                || record.stress_safe_point_count != stress.observed_safe_point_count
                || record.stress_rendezvous_count != stress.observed_rendezvous_count
                || record.stress_property_failures != stress.property_failures
                || record.stress_property_failures != 0
            {
                return Err(SemanticInvariantError::SmpScalingBenchmarkInvalid {
                    benchmark: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpScalingBenchmarkRecorded {
                            benchmark,
                            stress_run,
                            stress_run_generation,
                            hart_count,
                            workload_units,
                            measured_smp_nanos,
                            budget_nanos,
                            speedup_milli,
                            efficiency_milli,
                            generation,
                        } if *benchmark == record.id
                            && *stress_run == record.stress_run
                            && *stress_run_generation == record.stress_run_generation
                            && *hart_count == record.hart_count
                            && *workload_units == record.workload_units
                            && *measured_smp_nanos == record.measured_smp_nanos
                            && *budget_nanos == record.budget_nanos
                            && *speedup_milli == record.speedup_milli
                            && *efficiency_milli == record.efficiency_milli
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpScalingBenchmarkMissingEvent {
                    benchmark: record.id,
                });
            }
        }
        Ok(())
    }

    fn derive_scaling_speedup_milli(baseline_nanos: u64, measured_nanos: u64) -> Option<u64> {
        if measured_nanos == 0 {
            return None;
        }
        baseline_nanos.checked_mul(1_000)?.checked_div(measured_nanos)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_scaling_benchmark_speedup_for_test(
        &mut self,
        benchmark: SmpScalingBenchmarkId,
        speedup_milli: u64,
    ) {
        if let Some(record) =
            self.smp_scaling_benchmarks.iter_mut().find(|record| record.id == benchmark)
        {
            record.speedup_milli = speedup_milli;
        }
    }
}
