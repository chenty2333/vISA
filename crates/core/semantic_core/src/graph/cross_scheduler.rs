use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_cross_hart_scheduler_decision(
        &self,
        cross_decision: CrossHartSchedulerDecisionId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        deciding_hart: HartId,
        deciding_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: &str,
    ) -> Result<(), &'static str> {
        if cross_decision == 0 {
            return Err("cross-hart scheduler decision id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("cross-hart scheduler decision reason is empty");
        }
        if deciding_hart == target_hart {
            return Err("cross-hart scheduler decision requires distinct harts");
        }
        if self.cross_hart_scheduler_decisions.iter().any(|record| record.id == cross_decision) {
            return Err("cross-hart scheduler decision already exists");
        }
        let Some(decision) = self.scheduler_decisions.iter().find(|record| {
            record.id == scheduler_decision
                && record.generation == scheduler_decision_generation
                && record.state == SchedulerDecisionState::Recorded
        }) else {
            return Err("cross-hart scheduler decision base decision is missing");
        };
        let Some(deciding) = self.harts.iter().find(|record| {
            record.id == deciding_hart && record.generation == deciding_hart_generation
        }) else {
            return Err("cross-hart scheduler decision deciding hart generation is missing");
        };
        if matches!(deciding.state, HartState::Offline | HartState::Faulted | HartState::Parked) {
            return Err("cross-hart scheduler decision deciding hart is inactive");
        }
        let Some(target) = self
            .harts
            .iter()
            .find(|record| record.id == target_hart && record.generation == target_hart_generation)
        else {
            return Err("cross-hart scheduler decision target hart generation is missing");
        };
        if matches!(target.state, HartState::Offline | HartState::Faulted | HartState::Parked) {
            return Err("cross-hart scheduler decision target hart is inactive");
        }
        let Some(queue) = self.runnable_queues.iter().find(|record| {
            record.id == decision.queue
                && record.generation == decision.queue_generation
                && record.state == RunnableQueueState::Active
        }) else {
            return Err("cross-hart scheduler decision queue generation is missing");
        };
        if queue.owner_hart != Some(target_hart)
            || queue
                .owner_hart_generation
                .is_none_or(|generation| generation > target_hart_generation)
        {
            return Err("cross-hart scheduler decision queue owner mismatch");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_cross_hart_scheduler_decision_with_id(
        &mut self,
        cross_decision: CrossHartSchedulerDecisionId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        deciding_hart: HartId,
        deciding_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_cross_hart_scheduler_decision(
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
            )
            .is_err()
        {
            return false;
        }
        let Some(decision) = self
            .scheduler_decisions
            .iter()
            .find(|record| {
                record.id == scheduler_decision
                    && record.generation == scheduler_decision_generation
                    && record.state == SchedulerDecisionState::Recorded
            })
            .cloned()
        else {
            return false;
        };
        let Some(queue) = self.runnable_queues.iter().find(|record| {
            record.id == decision.queue
                && record.generation == decision.queue_generation
                && record.state == RunnableQueueState::Active
        }) else {
            return false;
        };
        let Some(queue_owner_hart_generation) = queue.owner_hart_generation else {
            return false;
        };

        self.next_cross_hart_scheduler_decision_id =
            self.next_cross_hart_scheduler_decision_id.max(cross_decision + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::CrossHartSchedulerDecisionRecorded {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                queue: decision.queue,
                queue_generation: decision.queue_generation,
                activation: decision.selected_activation,
                activation_generation: decision.selected_activation_generation,
                generation: 1,
            },
        );
        self.cross_hart_scheduler_decisions.push(CrossHartSchedulerDecisionRecord {
            id: cross_decision,
            scheduler_decision,
            scheduler_decision_generation,
            deciding_hart,
            deciding_hart_generation,
            target_hart,
            target_hart_generation,
            queue: decision.queue,
            queue_generation: decision.queue_generation,
            queue_owner_hart_generation,
            selected_activation: decision.selected_activation,
            selected_activation_generation: decision.selected_activation_generation,
            generation: 1,
            state: CrossHartSchedulerDecisionState::Recorded,
            decided_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            deciding_hart,
            deciding_hart_generation,
            event,
            "CrossHartSchedulerDecisionSourceRecorded",
            None,
            None,
            note,
        );
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation,
            event,
            "CrossHartSchedulerDecisionTargetRecorded",
            Some(decision.selected_activation),
            Some(decision.selected_activation_generation),
            note,
        );
        true
    }

    pub fn cross_hart_scheduler_decisions(&self) -> &[CrossHartSchedulerDecisionRecord] {
        &self.cross_hart_scheduler_decisions
    }

    pub fn cross_hart_scheduler_decision_count(&self) -> usize {
        self.cross_hart_scheduler_decisions.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_cross_hart_scheduler_decision_event_for_test(
        &mut self,
        cross_decision: CrossHartSchedulerDecisionId,
        event: EventId,
    ) {
        if let Some(record) = self
            .cross_hart_scheduler_decisions
            .iter_mut()
            .find(|record| record.id == cross_decision)
        {
            record.decided_at_event = event;
        }
    }

    pub fn check_cross_hart_scheduler_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cross in &self.cross_hart_scheduler_decisions {
            if cross.id == 0
                || cross.generation == 0
                || cross.scheduler_decision == 0
                || cross.scheduler_decision_generation == 0
                || cross.deciding_hart == 0
                || cross.target_hart == 0
                || cross.deciding_hart == cross.target_hart
                || cross.queue == 0
                || cross.queue_generation == 0
                || cross.queue_owner_hart_generation == 0
                || cross.selected_activation == 0
                || cross.selected_activation_generation == 0
                || cross.state != CrossHartSchedulerDecisionState::Recorded
            {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionInvalid {
                    cross_decision: cross.id,
                });
            }
            let Some(decision) = self.scheduler_decisions.iter().find(|record| {
                record.id == cross.scheduler_decision
                    && record.generation == cross.scheduler_decision_generation
                    && record.state != SchedulerDecisionState::Dropped
            }) else {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingDecision {
                    cross_decision: cross.id,
                    decision: cross.scheduler_decision,
                });
            };
            if decision.queue != cross.queue
                || decision.queue_generation != cross.queue_generation
                || decision.selected_activation != cross.selected_activation
                || decision.selected_activation_generation != cross.selected_activation_generation
            {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingDecision {
                    cross_decision: cross.id,
                    decision: cross.scheduler_decision,
                });
            }
            let Some(deciding) = self.harts.iter().find(|record| record.id == cross.deciding_hart)
            else {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingHart {
                    cross_decision: cross.id,
                    hart: cross.deciding_hart,
                });
            };
            if deciding.generation < cross.deciding_hart_generation {
                return Err(
                    SemanticInvariantError::CrossHartSchedulerDecisionHartGenerationMismatch {
                        cross_decision: cross.id,
                        hart: cross.deciding_hart,
                    },
                );
            }
            let Some(target) = self.harts.iter().find(|record| record.id == cross.target_hart)
            else {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingHart {
                    cross_decision: cross.id,
                    hart: cross.target_hart,
                });
            };
            if target.generation < cross.target_hart_generation {
                return Err(
                    SemanticInvariantError::CrossHartSchedulerDecisionHartGenerationMismatch {
                        cross_decision: cross.id,
                        hart: cross.target_hart,
                    },
                );
            }
            let Some(queue) = self.runnable_queues.iter().find(|record| record.id == cross.queue)
            else {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionQueueOwnerMismatch {
                    cross_decision: cross.id,
                    queue: cross.queue,
                });
            };
            if queue.generation < cross.queue_generation
                || (queue.generation == cross.queue_generation
                    && (queue.owner_hart != Some(cross.target_hart)
                        || queue.owner_hart_generation != Some(cross.queue_owner_hart_generation)
                        || cross.queue_owner_hart_generation > cross.target_hart_generation))
            {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionQueueOwnerMismatch {
                    cross_decision: cross.id,
                    queue: cross.queue,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == cross.decided_at_event
                    && matches!(
                        &event.kind,
                        EventKind::CrossHartSchedulerDecisionRecorded {
                            cross_decision,
                            scheduler_decision,
                            scheduler_decision_generation,
                            deciding_hart,
                            deciding_hart_generation,
                            target_hart,
                            target_hart_generation,
                            queue,
                            queue_generation,
                            activation,
                            activation_generation,
                            generation,
                        } if *cross_decision == cross.id
                            && *scheduler_decision == cross.scheduler_decision
                            && *scheduler_decision_generation == cross.scheduler_decision_generation
                            && *deciding_hart == cross.deciding_hart
                            && *deciding_hart_generation == cross.deciding_hart_generation
                            && *target_hart == cross.target_hart
                            && *target_hart_generation == cross.target_hart_generation
                            && *queue == cross.queue
                            && *queue_generation == cross.queue_generation
                            && *activation == cross.selected_activation
                            && *activation_generation == cross.selected_activation_generation
                            && *generation == cross.generation
                    )
            }) {
                return Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingEvent {
                    cross_decision: cross.id,
                });
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == cross.decided_at_event
                    && attribution.hart == cross.deciding_hart
                    && attribution.hart_generation == cross.deciding_hart_generation
                    && attribution.event_kind == "CrossHartSchedulerDecisionSourceRecorded"
            }) || !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == cross.decided_at_event
                    && attribution.hart == cross.target_hart
                    && attribution.hart_generation == cross.target_hart_generation
                    && attribution.event_kind == "CrossHartSchedulerDecisionTargetRecorded"
                    && attribution.activation == Some(cross.selected_activation)
                    && attribution.activation_generation
                        == Some(cross.selected_activation_generation)
            }) {
                return Err(
                    SemanticInvariantError::CrossHartSchedulerDecisionMissingHartEventAttribution {
                        cross_decision: cross.id,
                        event: cross.decided_at_event,
                    },
                );
            }
        }
        Ok(())
    }
}
