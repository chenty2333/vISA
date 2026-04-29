use super::*;

impl SemanticGraph {
    pub(crate) fn validate_smp_stress_run(
        &self,
        run: SmpStressRunId,
        scenario: &str,
        iterations: u32,
        invariant_checks: u32,
        reason: &str,
    ) -> Result<(), &'static str> {
        if run == 0 {
            return Err("smp stress run id=0 is invalid");
        }
        if self.domains.scheduler.smp_stress_runs.iter().any(|record| record.id == run) {
            return Err("smp stress run already exists");
        }
        if scenario.is_empty() {
            return Err("smp stress run scenario is empty");
        }
        if reason.is_empty() {
            return Err("smp stress run reason is empty");
        }
        if iterations < 3 {
            return Err("smp stress run requires at least three iterations");
        }
        if invariant_checks < iterations {
            return Err("smp stress run invariant checks must cover every iteration");
        }
        if self.active_hart_count() < 2 {
            return Err("smp stress run requires at least two active harts");
        }
        if self.smp_safe_point_count() < iterations as usize {
            return Err("smp stress run safe point coverage is incomplete");
        }
        if self.stop_the_world_rendezvous_count() < iterations as usize {
            return Err("smp stress run rendezvous coverage is incomplete");
        }
        if self.smp_code_publish_barrier_count() == 0 {
            return Err("smp stress run missing code publish barrier evidence");
        }
        if self.smp_cleanup_quiescence_count() == 0 {
            return Err("smp stress run missing cleanup quiescence evidence");
        }
        if self.smp_snapshot_barrier_count() == 0 {
            return Err("smp stress run missing snapshot barrier evidence");
        }
        if self.activation_migration_count() == 0 {
            return Err("smp stress run missing activation migration evidence");
        }
        if self.remote_preempt_count() == 0 {
            return Err("smp stress run missing remote preempt evidence");
        }
        if self.remote_park_count() == 0 {
            return Err("smp stress run missing remote park evidence");
        }
        if self.check_invariants().is_err() {
            return Err("smp stress run requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_smp_stress_run_with_id(
        &mut self,
        run: SmpStressRunId,
        scenario: &str,
        iterations: u32,
        invariant_checks: u32,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_stress_run(run, scenario, iterations, invariant_checks, reason)
            .is_err()
        {
            return false;
        }

        let Some((last_safe_point, last_safe_point_generation)) = self.latest_smp_safe_point_ref()
        else {
            return false;
        };
        let Some((last_rendezvous, last_rendezvous_generation)) = self.latest_rendezvous_ref()
        else {
            return false;
        };
        let Some((last_code_publish_barrier, last_code_publish_barrier_generation)) =
            self.latest_smp_code_publish_barrier_ref()
        else {
            return false;
        };
        let Some((last_cleanup_quiescence, last_cleanup_quiescence_generation)) =
            self.latest_smp_cleanup_quiescence_ref()
        else {
            return false;
        };
        let Some((last_snapshot_barrier, last_snapshot_barrier_generation)) =
            self.latest_smp_snapshot_barrier_ref()
        else {
            return false;
        };
        let Some((last_activation_migration, last_activation_migration_generation)) =
            self.latest_activation_migration_ref()
        else {
            return false;
        };
        let Some((last_remote_preempt, last_remote_preempt_generation)) =
            self.latest_remote_preempt_ref()
        else {
            return false;
        };
        let Some((last_remote_park, last_remote_park_generation)) = self.latest_remote_park_ref()
        else {
            return false;
        };

        let event_log_cursor = self.event_log.cursor();
        let hart_count = self.active_hart_count() as u32;
        let safe_point_count = self.smp_safe_point_count() as u32;
        let rendezvous_count = self.stop_the_world_rendezvous_count() as u32;
        let generation = 1;
        self.domains.scheduler.next_smp_stress_run_id =
            self.domains.scheduler.next_smp_stress_run_id.max(run + 1);
        let recorded_at_event = self.event_log.push(
            "scheduler",
            EventKind::SmpStressRunRecorded {
                run,
                scenario: scenario.to_string(),
                iterations,
                hart_count,
                safe_point_count,
                rendezvous_count,
                property_failures: 0,
                generation,
            },
        );
        self.domains.scheduler.smp_stress_runs.push(SmpStressRunRecord {
            id: run,
            scenario: scenario.to_string(),
            iterations,
            hart_count,
            event_log_cursor,
            observed_safe_point_count: safe_point_count,
            observed_rendezvous_count: rendezvous_count,
            observed_code_publish_barrier_count: self.smp_code_publish_barrier_count() as u32,
            observed_cleanup_quiescence_count: self.smp_cleanup_quiescence_count() as u32,
            observed_snapshot_barrier_count: self.smp_snapshot_barrier_count() as u32,
            observed_activation_migration_count: self.activation_migration_count() as u32,
            observed_remote_preempt_count: self.remote_preempt_count() as u32,
            observed_remote_park_count: self.remote_park_count() as u32,
            invariant_checks,
            property_failures: 0,
            last_safe_point,
            last_safe_point_generation,
            last_rendezvous,
            last_rendezvous_generation,
            last_code_publish_barrier,
            last_code_publish_barrier_generation,
            last_cleanup_quiescence,
            last_cleanup_quiescence_generation,
            last_snapshot_barrier,
            last_snapshot_barrier_generation,
            last_activation_migration,
            last_activation_migration_generation,
            last_remote_preempt,
            last_remote_preempt_generation,
            last_remote_park,
            last_remote_park_generation,
            generation,
            state: SmpStressRunState::Recorded,
            recorded_at_event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        true
    }

    pub fn smp_stress_runs(&self) -> &[SmpStressRunRecord] {
        &self.domains.scheduler.smp_stress_runs
    }

    pub fn smp_stress_run_count(&self) -> usize {
        self.domains.scheduler.smp_stress_runs.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_stress_run_failures_for_test(
        &mut self,
        run: SmpStressRunId,
        property_failures: u32,
    ) {
        if let Some(record) =
            self.domains.scheduler.smp_stress_runs.iter_mut().find(|record| record.id == run)
        {
            record.property_failures = property_failures;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_stress_run_snapshot_count_for_test(
        &mut self,
        run: SmpStressRunId,
        snapshot_barriers: u32,
    ) {
        if let Some(record) =
            self.domains.scheduler.smp_stress_runs.iter_mut().find(|record| record.id == run)
        {
            record.observed_snapshot_barrier_count = snapshot_barriers;
        }
    }

    pub fn check_smp_stress_run_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.scheduler.smp_stress_runs {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.reason.is_empty()
                || record.iterations < 3
                || record.hart_count < 2
                || record.event_log_cursor == 0
                || record.event_log_cursor >= record.recorded_at_event
                || record.invariant_checks < record.iterations
                || record.property_failures != 0
                || record.state != SmpStressRunState::Recorded
                || record.observed_safe_point_count < record.iterations
                || record.observed_rendezvous_count < record.iterations
                || record.observed_code_publish_barrier_count == 0
                || record.observed_cleanup_quiescence_count == 0
                || record.observed_snapshot_barrier_count == 0
                || record.observed_activation_migration_count == 0
                || record.observed_remote_preempt_count == 0
                || record.observed_remote_park_count == 0
            {
                return Err(SemanticInvariantError::SmpStressRunInvalid { run: record.id });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpStressRunRecorded {
                            run,
                            scenario,
                            iterations,
                            hart_count,
                            safe_point_count,
                            rendezvous_count,
                            property_failures,
                            generation,
                        } if *run == record.id
                            && scenario == &record.scenario
                            && *iterations == record.iterations
                            && *hart_count == record.hart_count
                            && *safe_point_count == record.observed_safe_point_count
                            && *rendezvous_count == record.observed_rendezvous_count
                            && *property_failures == record.property_failures
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpStressRunMissingEvent { run: record.id });
            }
            self.check_stress_ref(
                record.id,
                "smp-safe-point",
                record.last_safe_point,
                record.last_safe_point_generation,
                self.domains
                    .scheduler
                    .smp_safe_points
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "stop-the-world-rendezvous",
                record.last_rendezvous,
                record.last_rendezvous_generation,
                self.domains
                    .scheduler
                    .stop_the_world_rendezvous
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "smp-code-publish-barrier",
                record.last_code_publish_barrier,
                record.last_code_publish_barrier_generation,
                self.domains
                    .scheduler
                    .smp_code_publish_barriers
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "smp-cleanup-quiescence",
                record.last_cleanup_quiescence,
                record.last_cleanup_quiescence_generation,
                self.domains
                    .scheduler
                    .smp_cleanup_quiescence
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "smp-snapshot-barrier",
                record.last_snapshot_barrier,
                record.last_snapshot_barrier_generation,
                self.domains
                    .scheduler
                    .smp_snapshot_barriers
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "activation-migration",
                record.last_activation_migration,
                record.last_activation_migration_generation,
                self.domains
                    .scheduler
                    .activation_migrations
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "remote-preempt",
                record.last_remote_preempt,
                record.last_remote_preempt_generation,
                self.domains
                    .scheduler
                    .remote_preempts
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_stress_ref(
                record.id,
                "remote-park",
                record.last_remote_park,
                record.last_remote_park_generation,
                self.domains.scheduler.remote_parks.iter().map(|item| (item.id, item.generation)),
            )?;
            if record.observed_safe_point_count as usize > self.smp_safe_point_count()
                || record.observed_rendezvous_count as usize
                    > self.stop_the_world_rendezvous_count()
                || record.observed_code_publish_barrier_count as usize
                    > self.smp_code_publish_barrier_count()
                || record.observed_cleanup_quiescence_count as usize
                    > self.smp_cleanup_quiescence_count()
                || record.observed_snapshot_barrier_count as usize
                    > self.smp_snapshot_barrier_count()
                || record.observed_activation_migration_count as usize
                    > self.activation_migration_count()
                || record.observed_remote_preempt_count as usize > self.remote_preempt_count()
                || record.observed_remote_park_count as usize > self.remote_park_count()
            {
                return Err(SemanticInvariantError::SmpStressRunInvalid { run: record.id });
            }
        }
        Ok(())
    }

    fn active_hart_count(&self) -> usize {
        self.domains
            .scheduler
            .harts
            .iter()
            .filter(|record| !matches!(record.state, HartState::Offline | HartState::Faulted))
            .count()
    }

    fn check_stress_ref<I>(
        &self,
        run: SmpStressRunId,
        evidence: &'static str,
        id: u64,
        generation: Generation,
        refs: I,
    ) -> Result<(), SemanticInvariantError>
    where
        I: Iterator<Item = (u64, Generation)>,
    {
        if id == 0 || generation == 0 || !refs.into_iter().any(|item| item == (id, generation)) {
            return Err(SemanticInvariantError::SmpStressRunMissingEvidence { run, evidence });
        }
        Ok(())
    }

    fn latest_smp_safe_point_ref(&self) -> Option<(SmpSafePointId, Generation)> {
        self.domains.scheduler.smp_safe_points.last().map(|record| (record.id, record.generation))
    }

    fn latest_rendezvous_ref(&self) -> Option<(StopTheWorldRendezvousId, Generation)> {
        self.domains
            .scheduler
            .stop_the_world_rendezvous
            .last()
            .map(|record| (record.id, record.generation))
    }

    fn latest_smp_code_publish_barrier_ref(&self) -> Option<(SmpCodePublishBarrierId, Generation)> {
        self.domains
            .scheduler
            .smp_code_publish_barriers
            .last()
            .map(|record| (record.id, record.generation))
    }

    fn latest_smp_cleanup_quiescence_ref(&self) -> Option<(SmpCleanupQuiescenceId, Generation)> {
        self.domains
            .scheduler
            .smp_cleanup_quiescence
            .last()
            .map(|record| (record.id, record.generation))
    }

    fn latest_smp_snapshot_barrier_ref(&self) -> Option<(SmpSnapshotBarrierId, Generation)> {
        self.domains
            .scheduler
            .smp_snapshot_barriers
            .last()
            .map(|record| (record.id, record.generation))
    }

    fn latest_activation_migration_ref(&self) -> Option<(ActivationMigrationId, Generation)> {
        self.domains
            .scheduler
            .activation_migrations
            .last()
            .map(|record| (record.id, record.generation))
    }

    fn latest_remote_preempt_ref(&self) -> Option<(RemotePreemptId, Generation)> {
        self.domains.scheduler.remote_preempts.last().map(|record| (record.id, record.generation))
    }

    fn latest_remote_park_ref(&self) -> Option<(RemoteParkId, Generation)> {
        self.domains.scheduler.remote_parks.last().map(|record| (record.id, record.generation))
    }
}
