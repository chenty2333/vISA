use super::*;

impl SemanticGraph {
    pub fn record_timer_interrupt_with_id(
        &mut self,
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: HartId,
        hart_generation: Generation,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
        note: &str,
    ) -> bool {
        if interrupt == 0
            || timer_epoch == 0
            || self
                .timer_interrupts
                .iter()
                .any(|record| record.id == interrupt || record.timer_epoch == timer_epoch)
        {
            return false;
        }
        let Some(hart_record) = self
            .harts
            .iter()
            .find(|record| record.id == hart && record.generation == hart_generation)
        else {
            return false;
        };
        if matches!(hart_record.state, HartState::Offline | HartState::Faulted) {
            return false;
        }
        let hardware_hart = hart_record.hardware_id;
        if let Some(previous) = self.timer_interrupts.iter().map(|record| record.timer_epoch).max()
            && timer_epoch <= previous
        {
            return false;
        }
        let (target_task, target_task_generation) = if let Some(activation) = target_activation {
            let Some(generation) = target_activation_generation else {
                return false;
            };
            let Some(record) = self
                .runtime_activations
                .iter()
                .find(|record| record.id == activation && record.generation == generation)
            else {
                return false;
            };
            if matches!(record.state, RuntimeActivationState::Dead | RuntimeActivationState::Exited)
            {
                return false;
            }
            (Some(record.owner_task), Some(record.owner_task_generation))
        } else {
            (None, None)
        };

        self.next_timer_interrupt_id = self.next_timer_interrupt_id.max(interrupt + 1);
        let event = self.event_log.push(
            "timer",
            EventKind::TimerInterruptRecorded {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                hardware_hart,
                target_activation,
                target_activation_generation,
                generation: 1,
            },
        );
        self.timer_interrupts.push(TimerInterruptRecord {
            id: interrupt,
            timer_epoch,
            hart,
            hart_generation,
            hardware_hart,
            target_activation,
            target_activation_generation,
            target_task,
            target_task_generation,
            generation: 1,
            state: TimerInterruptState::Recorded,
            recorded_at_event: event,
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            hart,
            hart_generation,
            event,
            "TimerInterruptRecorded",
            target_activation,
            target_activation_generation,
            note,
        );
        true
    }

    pub fn timer_interrupts(&self) -> &[TimerInterruptRecord] {
        &self.timer_interrupts
    }

    pub fn timer_interrupt_count(&self) -> usize {
        self.timer_interrupts.len()
    }

    pub fn timer_epoch(&self) -> u64 {
        self.timer_interrupts.iter().map(|record| record.timer_epoch).max().unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_timer_interrupt_epoch_for_test(
        &mut self,
        interrupt: TimerInterruptId,
        timer_epoch: u64,
    ) {
        if let Some(record) = self.timer_interrupts.iter_mut().find(|record| record.id == interrupt)
        {
            record.timer_epoch = timer_epoch;
        }
    }

    pub fn check_timer_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut previous_epoch = 0;
        for interrupt in &self.timer_interrupts {
            if interrupt.timer_epoch == 0 || interrupt.timer_epoch <= previous_epoch {
                return Err(SemanticInvariantError::TimerInterruptEpochNonMonotonic {
                    interrupt: interrupt.id,
                    timer_epoch: interrupt.timer_epoch,
                });
            }
            previous_epoch = interrupt.timer_epoch;
            match (
                self.harts.iter().find(|record| record.id == interrupt.hart),
                interrupt.hart_generation,
            ) {
                (Some(hart), generation)
                    if generation != 0
                        && hart.generation >= generation
                        && hart.hardware_id == interrupt.hardware_hart => {}
                (Some(_), _) => {
                    return Err(SemanticInvariantError::TimerInterruptHartMismatch {
                        interrupt: interrupt.id,
                        hart: interrupt.hart,
                    });
                }
                (None, _) => {
                    return Err(SemanticInvariantError::TimerInterruptMissingHart {
                        interrupt: interrupt.id,
                        hart: interrupt.hart,
                    });
                }
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == interrupt.recorded_at_event
                    && attribution.hart == interrupt.hart
                    && attribution.hart_generation == interrupt.hart_generation
                    && attribution.event_kind == "TimerInterruptRecorded"
            }) {
                return Err(SemanticInvariantError::TimerInterruptMissingHartEventAttribution {
                    interrupt: interrupt.id,
                    event: interrupt.recorded_at_event,
                });
            }
            match (interrupt.target_activation, interrupt.target_activation_generation) {
                (Some(activation), Some(generation)) => {
                    let Some(record) = self
                        .runtime_activations
                        .iter()
                        .find(|record| record.id == activation && record.generation == generation)
                    else {
                        if self.preemptions.iter().any(|preemption| {
                            preemption.activation == activation
                                && preemption.activation_generation_before == generation
                                && preemption.timer_interrupt == interrupt.id
                                && preemption.timer_interrupt_generation == interrupt.generation
                        }) {
                            continue;
                        }
                        return Err(SemanticInvariantError::TimerInterruptMissingActivation {
                            interrupt: interrupt.id,
                            activation,
                        });
                    };
                    if matches!(
                        record.state,
                        RuntimeActivationState::Dead | RuntimeActivationState::Exited
                    ) {
                        return Err(SemanticInvariantError::TimerInterruptTargetsDeadActivation {
                            interrupt: interrupt.id,
                            activation,
                        });
                    }
                    if interrupt.target_task != Some(record.owner_task)
                        || interrupt.target_task_generation != Some(record.owner_task_generation)
                    {
                        return Err(SemanticInvariantError::TimerInterruptTargetTaskMismatch {
                            interrupt: interrupt.id,
                            activation,
                        });
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(
                        SemanticInvariantError::TimerInterruptMissingActivationGeneration {
                            interrupt: interrupt.id,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}
