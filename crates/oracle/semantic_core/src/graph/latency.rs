use super::*;

struct PreemptionLatencyChain {
    activation: ActivationId,
    activation_generation_before: Generation,
    activation_generation_after: Generation,
    queue: RunnableQueueId,
    queue_generation: Generation,
    interrupt_recorded_at_event: EventId,
    preempted_at_event: EventId,
    decided_at_event: EventId,
    resumed_at_event: EventId,
}

impl SemanticGraph {
    pub(crate) fn validate_preemption_latency_sample(
        &self,
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
        measured_nanos: u64,
        budget_nanos: u64,
    ) -> Result<(), &'static str> {
        if sample == 0 {
            return Err("preemption latency sample id=0 is invalid");
        }
        if self
            .domains
            .scheduler
            .preemption_latency_samples
            .iter()
            .any(|record| record.id == sample)
        {
            return Err("preemption latency sample already exists");
        }
        if measured_nanos == 0 {
            return Err("preemption latency measured nanos must be nonzero");
        }
        if budget_nanos == 0 {
            return Err("preemption latency budget nanos must be nonzero");
        }
        self.preemption_latency_chain(
            sample,
            timer_interrupt,
            timer_interrupt_generation,
            preemption,
            preemption_generation,
            scheduler_decision,
            scheduler_decision_generation,
            activation_resume,
            activation_resume_generation,
        )
        .map(|_| ())
        .map_err(|_| "preemption latency chain is invalid")
    }

    pub fn record_preemption_latency_sample_with_id(
        &mut self,
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
        measured_nanos: u64,
        budget_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_preemption_latency_sample(
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
            )
            .is_err()
        {
            return false;
        }
        let chain = self
            .preemption_latency_chain(
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
            )
            .expect("preemption latency chain was validated");
        self.domains.scheduler.next_preemption_latency_sample_id =
            self.domains.scheduler.next_preemption_latency_sample_id.max(sample + 1);
        let generation = 1;
        let recorded_at_event = self.event_log.push(
            "scheduler",
            EventKind::PreemptionLatencySampleRecorded {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                generation,
            },
        );
        self.domains.scheduler.preemption_latency_samples.push(PreemptionLatencySampleRecord {
            id: sample,
            timer_interrupt,
            timer_interrupt_generation,
            preemption,
            preemption_generation,
            scheduler_decision,
            scheduler_decision_generation,
            activation_resume,
            activation_resume_generation,
            activation: chain.activation,
            activation_generation_before: chain.activation_generation_before,
            activation_generation_after: chain.activation_generation_after,
            queue: chain.queue,
            queue_generation: chain.queue_generation,
            interrupt_recorded_at_event: chain.interrupt_recorded_at_event,
            preempted_at_event: chain.preempted_at_event,
            decided_at_event: chain.decided_at_event,
            resumed_at_event: chain.resumed_at_event,
            interrupt_to_preempt_events: chain
                .preempted_at_event
                .saturating_sub(chain.interrupt_recorded_at_event),
            preempt_to_decision_events: chain
                .decided_at_event
                .saturating_sub(chain.preempted_at_event),
            decision_to_resume_events: chain
                .resumed_at_event
                .saturating_sub(chain.decided_at_event),
            interrupt_to_resume_events: chain
                .resumed_at_event
                .saturating_sub(chain.interrupt_recorded_at_event),
            measured_nanos,
            budget_nanos,
            generation,
            state: PreemptionLatencySampleState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn preemption_latency_samples(&self) -> &[PreemptionLatencySampleRecord] {
        &self.domains.scheduler.preemption_latency_samples
    }

    pub fn preemption_latency_sample_count(&self) -> usize {
        self.domains.scheduler.preemption_latency_samples.len()
    }

    pub fn check_preemption_latency_invariants(&self) -> Result<(), SemanticInvariantError> {
        for sample in &self.domains.scheduler.preemption_latency_samples {
            let chain = self.preemption_latency_chain(
                sample.id,
                sample.timer_interrupt,
                sample.timer_interrupt_generation,
                sample.preemption,
                sample.preemption_generation,
                sample.scheduler_decision,
                sample.scheduler_decision_generation,
                sample.activation_resume,
                sample.activation_resume_generation,
            )?;
            if sample.activation != chain.activation
                || sample.activation_generation_before != chain.activation_generation_before
                || sample.activation_generation_after != chain.activation_generation_after
                || sample.queue != chain.queue
                || sample.queue_generation != chain.queue_generation
                || sample.interrupt_recorded_at_event != chain.interrupt_recorded_at_event
                || sample.preempted_at_event != chain.preempted_at_event
                || sample.decided_at_event != chain.decided_at_event
                || sample.resumed_at_event != chain.resumed_at_event
                || sample.interrupt_to_preempt_events
                    != chain.preempted_at_event.saturating_sub(chain.interrupt_recorded_at_event)
                || sample.preempt_to_decision_events
                    != chain.decided_at_event.saturating_sub(chain.preempted_at_event)
                || sample.decision_to_resume_events
                    != chain.resumed_at_event.saturating_sub(chain.decided_at_event)
                || sample.interrupt_to_resume_events
                    != chain.resumed_at_event.saturating_sub(chain.interrupt_recorded_at_event)
                || sample.measured_nanos == 0
                || sample.budget_nanos == 0
            {
                return Err(SemanticInvariantError::PreemptionLatencyTimelineMismatch {
                    sample: sample.id,
                });
            }
        }
        Ok(())
    }

    fn preemption_latency_chain(
        &self,
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
    ) -> Result<PreemptionLatencyChain, SemanticInvariantError> {
        let Some(timer) = self.domains.scheduler.timer_interrupts.iter().find(|record| {
            record.id == timer_interrupt && record.generation == timer_interrupt_generation
        }) else {
            return Err(SemanticInvariantError::PreemptionLatencyMissingTimerInterrupt {
                sample,
                interrupt: timer_interrupt,
            });
        };
        let Some(preempt) = self.domains.scheduler.preemptions.iter().find(|record| {
            record.id == preemption
                && record.generation == preemption_generation
                && record.timer_interrupt == timer_interrupt
                && record.timer_interrupt_generation == timer_interrupt_generation
                && record.state == PreemptionState::Applied
        }) else {
            return Err(SemanticInvariantError::PreemptionLatencyMissingPreemption {
                sample,
                preemption,
            });
        };
        if timer.target_activation != Some(preempt.activation)
            || timer.target_activation_generation != Some(preempt.activation_generation_before)
        {
            return Err(SemanticInvariantError::PreemptionLatencyTimelineMismatch { sample });
        }
        let Some(decision) = self.domains.scheduler.scheduler_decisions.iter().find(|record| {
            record.id == scheduler_decision
                && record.generation == scheduler_decision_generation
                && record.queue == preempt.queue
                && record.queue_generation == preempt.queue_generation
                && record.selected_activation == preempt.activation
                && record.selected_activation_generation == preempt.activation_generation_after
                && matches!(
                    record.state,
                    SchedulerDecisionState::Recorded | SchedulerDecisionState::Superseded
                )
        }) else {
            return Err(SemanticInvariantError::PreemptionLatencyMissingDecision {
                sample,
                decision: scheduler_decision,
            });
        };
        let Some(resume) = self.domains.scheduler.activation_resumes.iter().find(|record| {
            record.id == activation_resume
                && record.generation == activation_resume_generation
                && record.scheduler_decision == scheduler_decision
                && record.scheduler_decision_generation == scheduler_decision_generation
                && record.activation == preempt.activation
                && record.activation_generation_before == decision.selected_activation_generation
                && record.queue == preempt.queue
                && record.queue_generation == preempt.queue_generation
                && record.state == ActivationResumeState::Applied
        }) else {
            return Err(SemanticInvariantError::PreemptionLatencyMissingResume {
                sample,
                resume: activation_resume,
            });
        };
        if timer.recorded_at_event > preempt.preempted_at_event
            || preempt.preempted_at_event > decision.decided_at_event
            || decision.decided_at_event > resume.resumed_at_event
        {
            return Err(SemanticInvariantError::PreemptionLatencyTimelineMismatch { sample });
        }
        Ok(PreemptionLatencyChain {
            activation: preempt.activation,
            activation_generation_before: preempt.activation_generation_before,
            activation_generation_after: resume.activation_generation_after,
            queue: preempt.queue,
            queue_generation: preempt.queue_generation,
            interrupt_recorded_at_event: timer.recorded_at_event,
            preempted_at_event: preempt.preempted_at_event,
            decided_at_event: decision.decided_at_event,
            resumed_at_event: resume.resumed_at_event,
        })
    }

    #[cfg(test)]
    pub(crate) fn corrupt_preemption_latency_interrupt_to_resume_for_test(
        &mut self,
        sample: PreemptionLatencySampleId,
        value: u64,
    ) {
        if let Some(record) = self
            .domains
            .scheduler
            .preemption_latency_samples
            .iter_mut()
            .find(|record| record.id == sample)
        {
            record.interrupt_to_resume_events = value;
        }
    }
}
