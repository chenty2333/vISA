use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_smp_preemption_cleanup(
        &self,
        integrated: IntegratedSmpPreemptionCleanupId,
        scenario: &str,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        saved_context: SavedContextId,
        saved_context_generation: Generation,
        remote_preempt: RemotePreemptId,
        remote_preempt_generation: Generation,
        activation_cleanup: ActivationCleanupId,
        activation_cleanup_generation: Generation,
        smp_cleanup_quiescence: SmpCleanupQuiescenceId,
        smp_cleanup_quiescence_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated smp/preemption/cleanup id=0 is invalid");
        }
        if self.integrated_smp_preemption_cleanups.iter().any(|record| record.id == integrated) {
            return Err("integrated smp/preemption/cleanup evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated smp/preemption/cleanup scenario is empty");
        }
        if stress_run_generation == 0
            || preemption_generation == 0
            || timer_interrupt_generation == 0
            || saved_context_generation == 0
            || remote_preempt_generation == 0
            || activation_cleanup_generation == 0
            || smp_cleanup_quiescence_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated smp/preemption/cleanup refs must carry generations");
        }

        let Some(stress) =
            self.domains.scheduler.smp_stress_runs.iter().find(|record| {
                record.id == stress_run && record.generation == stress_run_generation
            })
        else {
            return Err("integrated smp/preemption/cleanup missing stress run evidence");
        };
        if stress.state != SmpStressRunState::Recorded
            || stress.property_failures != 0
            || stress.hart_count < 2
            || stress.observed_remote_preempt_count == 0
            || stress.observed_cleanup_quiescence_count == 0
            || stress.invariant_checks > invariant_checks
        {
            return Err("integrated smp/preemption/cleanup requires clean SMP stress evidence");
        }

        let Some(timer) = self.domains.scheduler.timer_interrupts.iter().find(|record| {
            record.id == timer_interrupt && record.generation == timer_interrupt_generation
        }) else {
            return Err("integrated smp/preemption/cleanup missing timer interrupt evidence");
        };
        if timer.state == TimerInterruptState::Dropped
            || timer.target_activation.is_none()
            || timer.target_activation_generation.is_none()
        {
            return Err("integrated smp/preemption/cleanup requires delivered timer target");
        }

        let Some(preempt) =
            self.domains.scheduler.preemptions.iter().find(|record| {
                record.id == preemption && record.generation == preemption_generation
            })
        else {
            return Err("integrated smp/preemption/cleanup missing preemption evidence");
        };
        if preempt.state != PreemptionState::Applied
            || preempt.timer_interrupt != timer_interrupt
            || preempt.timer_interrupt_generation != timer_interrupt_generation
            || Some(preempt.activation) != timer.target_activation
            || Some(preempt.activation_generation_before) != timer.target_activation_generation
        {
            return Err("integrated smp/preemption/cleanup timer/preemption link mismatch");
        }

        let Some(saved) = self.domains.scheduler.saved_contexts.iter().find(|record| {
            record.id == saved_context && record.generation == saved_context_generation
        }) else {
            return Err("integrated smp/preemption/cleanup missing saved context evidence");
        };
        if saved.state == SavedContextState::Dropped
            || saved.source_preemption != Some(preemption)
            || saved.source_preemption_generation != Some(preemption_generation)
            || saved.activation != preempt.activation
            || saved.activation_generation != preempt.activation_generation_after
        {
            return Err("integrated smp/preemption/cleanup saved context link mismatch");
        }

        let Some(remote) = self.domains.scheduler.remote_preempts.iter().find(|record| {
            record.id == remote_preempt && record.generation == remote_preempt_generation
        }) else {
            return Err("integrated smp/preemption/cleanup missing remote preempt evidence");
        };
        if remote.state != RemotePreemptState::Applied
            || remote.source_hart == remote.target_hart
            || stress.last_remote_preempt != remote.id
            || stress.last_remote_preempt_generation != remote.generation
        {
            return Err("integrated smp/preemption/cleanup remote preempt mismatch");
        }

        let Some(cleanup) = self.domains.scheduler.activation_cleanups.iter().find(|record| {
            record.id == activation_cleanup && record.generation == activation_cleanup_generation
        }) else {
            return Err("integrated smp/preemption/cleanup missing activation cleanup evidence");
        };
        if cleanup.state != ActivationCleanupState::Completed
            || cleanup.result_store_generation <= cleanup.target_store_generation
            || cleanup.wait.is_none()
        {
            return Err(
                "integrated smp/preemption/cleanup requires completed wait-cancelling cleanup",
            );
        }

        let Some(quiescence) =
            self.domains.scheduler.smp_cleanup_quiescence.iter().find(|record| {
                record.id == smp_cleanup_quiescence
                    && record.generation == smp_cleanup_quiescence_generation
            })
        else {
            return Err("integrated smp/preemption/cleanup missing cleanup quiescence evidence");
        };
        if quiescence.state != SmpCleanupQuiescenceState::Validated
            || quiescence.cleanup != cleanup.id
            || quiescence.cleanup_generation != cleanup.generation
            || quiescence.store != cleanup.store
            || quiescence.target_store_generation != cleanup.target_store_generation
            || quiescence.result_store_generation != cleanup.result_store_generation
            || quiescence.activation != cleanup.activation
            || quiescence.activation_generation_after != cleanup.activation_generation_after
            || quiescence.participants.len() < 2
            || !quiescence.no_running_activation
            || !quiescence.no_pending_wait
            || !quiescence.no_live_capability
            || !quiescence.no_live_resource
            || stress.last_cleanup_quiescence != quiescence.id
            || stress.last_cleanup_quiescence_generation != quiescence.generation
        {
            return Err("integrated smp/preemption/cleanup quiescence mismatch");
        }

        if self.domains.scheduler.activation_resumes.iter().any(|resume| {
            resume.activation == cleanup.activation
                && resume.activation_generation_after >= cleanup.activation_generation_after
                && resume.resumed_at_event > cleanup.completed_at_event
        }) {
            return Err("integrated smp/preemption/cleanup found resume after cleanup");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_smp_preemption_cleanup_with_id(
        &mut self,
        integrated: IntegratedSmpPreemptionCleanupId,
        scenario: &str,
        stress_run: SmpStressRunId,
        stress_run_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        saved_context: SavedContextId,
        saved_context_generation: Generation,
        remote_preempt: RemotePreemptId,
        remote_preempt_generation: Generation,
        activation_cleanup: ActivationCleanupId,
        activation_cleanup_generation: Generation,
        smp_cleanup_quiescence: SmpCleanupQuiescenceId,
        smp_cleanup_quiescence_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_smp_preemption_cleanup(
                integrated,
                scenario,
                stress_run,
                stress_run_generation,
                preemption,
                preemption_generation,
                timer_interrupt,
                timer_interrupt_generation,
                saved_context,
                saved_context_generation,
                remote_preempt,
                remote_preempt_generation,
                activation_cleanup,
                activation_cleanup_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(stress) =
            self.domains.scheduler.smp_stress_runs.iter().find(|record| {
                record.id == stress_run && record.generation == stress_run_generation
            })
        else {
            return false;
        };
        let Some(cleanup) = self.domains.scheduler.activation_cleanups.iter().find(|record| {
            record.id == activation_cleanup && record.generation == activation_cleanup_generation
        }) else {
            return false;
        };
        let hart_count = stress.hart_count;
        let cleanup_store = cleanup.store;
        let target_store_generation = cleanup.target_store_generation;
        let result_store_generation = cleanup.result_store_generation;
        let cleanup_activation = cleanup.activation;
        let cleanup_activation_generation_after = cleanup.activation_generation_after;
        let generation = 1;
        self.next_integrated_smp_preemption_cleanup_id =
            self.next_integrated_smp_preemption_cleanup_id.max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedSmpPreemptionCleanupRecorded {
                scenario: scenario.to_string(),
                integrated,
                stress_run,
                stress_run_generation,
                preemption,
                preemption_generation,
                remote_preempt,
                remote_preempt_generation,
                activation_cleanup,
                activation_cleanup_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                cleanup_store,
                target_store_generation,
                result_store_generation,
                hart_count,
                invariant_checks,
                generation,
            },
        );
        self.integrated_smp_preemption_cleanups.push(IntegratedSmpPreemptionCleanupRecord {
            id: integrated,
            scenario: scenario.to_string(),
            stress_run,
            stress_run_generation,
            preemption,
            preemption_generation,
            timer_interrupt,
            timer_interrupt_generation,
            saved_context,
            saved_context_generation,
            remote_preempt,
            remote_preempt_generation,
            activation_cleanup,
            activation_cleanup_generation,
            smp_cleanup_quiescence,
            smp_cleanup_quiescence_generation,
            cleanup_store,
            target_store_generation,
            result_store_generation,
            cleanup_activation,
            cleanup_activation_generation_after,
            hart_count,
            invariant_checks,
            generation,
            state: IntegratedSmpPreemptionCleanupState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn integrated_smp_preemption_cleanups(&self) -> &[IntegratedSmpPreemptionCleanupRecord] {
        &self.integrated_smp_preemption_cleanups
    }

    pub fn integrated_smp_preemption_cleanup_count(&self) -> usize {
        self.integrated_smp_preemption_cleanups.len()
    }

    pub fn check_integrated_smp_preemption_cleanup_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_smp_preemption_cleanups {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpPreemptionCleanupState::Recorded
                || record.stress_run_generation == 0
                || record.preemption_generation == 0
                || record.timer_interrupt_generation == 0
                || record.saved_context_generation == 0
                || record.remote_preempt_generation == 0
                || record.activation_cleanup_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.target_store_generation == 0
                || record.result_store_generation <= record.target_store_generation
                || record.cleanup_activation_generation_after == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedSmpPreemptionCleanupInvalid {
                    integrated: record.id,
                });
            }
            self.check_integrated_evidence_ref(
                record.id,
                "smp-stress-run",
                record.stress_run,
                record.stress_run_generation,
                self.domains
                    .scheduler
                    .smp_stress_runs
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "preemption",
                record.preemption,
                record.preemption_generation,
                self.domains.scheduler.preemptions.iter().map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "timer-interrupt",
                record.timer_interrupt,
                record.timer_interrupt_generation,
                self.domains
                    .scheduler
                    .timer_interrupts
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "saved-context",
                record.saved_context,
                record.saved_context_generation,
                self.domains.scheduler.saved_contexts.iter().map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "remote-preempt",
                record.remote_preempt,
                record.remote_preempt_generation,
                self.domains
                    .scheduler
                    .remote_preempts
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "activation-cleanup",
                record.activation_cleanup,
                record.activation_cleanup_generation,
                self.domains
                    .scheduler
                    .activation_cleanups
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            self.check_integrated_evidence_ref(
                record.id,
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
                self.domains
                    .scheduler
                    .smp_cleanup_quiescence
                    .iter()
                    .map(|item| (item.id, item.generation)),
            )?;
            if self
                .validate_integrated_smp_preemption_cleanup(
                    u64::MAX,
                    &record.scenario,
                    record.stress_run,
                    record.stress_run_generation,
                    record.preemption,
                    record.preemption_generation,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    record.saved_context,
                    record.saved_context_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedSmpPreemptionCleanupInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedSmpPreemptionCleanupRecorded {
                            scenario,
                            integrated,
                            stress_run,
                            stress_run_generation,
                            preemption,
                            preemption_generation,
                            remote_preempt,
                            remote_preempt_generation,
                            activation_cleanup,
                            activation_cleanup_generation,
                            smp_cleanup_quiescence,
                            smp_cleanup_quiescence_generation,
                            cleanup_store,
                            target_store_generation,
                            result_store_generation,
                            hart_count,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *stress_run == record.stress_run
                            && *stress_run_generation == record.stress_run_generation
                            && *preemption == record.preemption
                            && *preemption_generation == record.preemption_generation
                            && *remote_preempt == record.remote_preempt
                            && *remote_preempt_generation == record.remote_preempt_generation
                            && *activation_cleanup == record.activation_cleanup
                            && *activation_cleanup_generation == record.activation_cleanup_generation
                            && *smp_cleanup_quiescence == record.smp_cleanup_quiescence
                            && *smp_cleanup_quiescence_generation == record.smp_cleanup_quiescence_generation
                            && *cleanup_store == record.cleanup_store
                            && *target_store_generation == record.target_store_generation
                            && *result_store_generation == record.result_store_generation
                            && *hart_count == record.hart_count
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::IntegratedSmpPreemptionCleanupMissingEvent {
                        integrated: record.id,
                    },
                );
            }
        }
        Ok(())
    }

    fn check_integrated_evidence_ref<I>(
        &self,
        integrated: IntegratedSmpPreemptionCleanupId,
        evidence: &'static str,
        id: u64,
        generation: Generation,
        refs: I,
    ) -> Result<(), SemanticInvariantError>
    where
        I: Iterator<Item = (u64, Generation)>,
    {
        if id == 0 || generation == 0 || !refs.into_iter().any(|item| item == (id, generation)) {
            return Err(SemanticInvariantError::IntegratedSmpPreemptionCleanupMissingEvidence {
                integrated,
                evidence,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_integrated_smp_cleanup_hart_count_for_test(
        &mut self,
        integrated: IntegratedSmpPreemptionCleanupId,
        hart_count: u32,
    ) {
        if let Some(record) = self
            .integrated_smp_preemption_cleanups
            .iter_mut()
            .find(|record| record.id == integrated)
        {
            record.hart_count = hart_count;
        }
    }
}
