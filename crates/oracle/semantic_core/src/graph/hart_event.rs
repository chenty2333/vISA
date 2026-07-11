use super::*;

impl SemanticGraph {
    pub(crate) fn push_hart_event_attribution(
        &mut self,
        hart: HartId,
        hart_generation: Generation,
        event: EventId,
        event_kind: &str,
        activation: Option<ActivationId>,
        activation_generation: Option<Generation>,
        note: &str,
    ) -> bool {
        let attribution = self.domains.scheduler.next_hart_event_attribution_id;
        self.record_hart_event_attribution_with_id(
            attribution,
            hart,
            hart_generation,
            event,
            event_kind,
            activation,
            activation_generation,
            note,
        )
    }

    pub(crate) fn record_hart_event_attribution_with_id(
        &mut self,
        attribution: HartEventAttributionId,
        hart: HartId,
        hart_generation: Generation,
        event: EventId,
        event_kind: &str,
        activation: Option<ActivationId>,
        activation_generation: Option<Generation>,
        note: &str,
    ) -> bool {
        if attribution == 0
            || hart == 0
            || hart_generation == 0
            || event == 0
            || event_kind.is_empty()
            || self.domains.scheduler.hart_event_attributions.iter().any(|record| {
                record.id == attribution || (record.hart == hart && record.event == event)
            })
        {
            return false;
        }
        let Some(hart_record) = self
            .domains
            .scheduler
            .harts
            .iter()
            .find(|record| record.id == hart && record.generation >= hart_generation)
        else {
            return false;
        };
        let hardware_hart = hart_record.hardware_id;
        let Some(event_record) = self.event_log.events.iter().find(|record| record.id == event)
        else {
            return false;
        };
        let event_source = event_record.source.clone();
        let (task, task_generation, store, store_generation) = if let Some(activation) = activation
        {
            let Some(generation) = activation_generation else {
                return false;
            };
            let Some(record) = self
                .domains
                .scheduler
                .runtime_activations
                .iter()
                .find(|record| record.id == activation && record.generation >= generation)
            else {
                return false;
            };
            (
                Some(record.owner_task),
                Some(record.owner_task_generation),
                record.owner_store,
                record.owner_store_generation,
            )
        } else if activation_generation.is_some() {
            return false;
        } else {
            (None, None, None, None)
        };

        self.domains.scheduler.next_hart_event_attribution_id =
            self.domains.scheduler.next_hart_event_attribution_id.max(attribution + 1);
        self.domains.scheduler.hart_event_attributions.push(HartEventAttributionRecord {
            id: attribution,
            hart,
            hart_generation,
            hardware_hart,
            event,
            event_source,
            event_kind: event_kind.to_string(),
            activation,
            activation_generation,
            task,
            task_generation,
            store,
            store_generation,
            generation: 1,
            state: HartEventAttributionState::Recorded,
            note: note.to_string(),
        });
        true
    }

    pub fn hart_event_attributions(&self) -> &[HartEventAttributionRecord] {
        &self.domains.scheduler.hart_event_attributions
    }

    pub fn hart_event_attribution_count(&self) -> usize {
        self.domains.scheduler.hart_event_attributions.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_hart_event_attribution_hart_generation_for_test(
        &mut self,
        attribution: HartEventAttributionId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .scheduler
            .hart_event_attributions
            .iter_mut()
            .find(|record| record.id == attribution)
        {
            record.hart_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn clear_hart_event_attributions_for_test(&mut self) {
        self.domains.scheduler.hart_event_attributions.clear();
    }

    pub fn check_hart_event_attribution_invariants(&self) -> Result<(), SemanticInvariantError> {
        for attribution in &self.domains.scheduler.hart_event_attributions {
            if attribution.id == 0
                || attribution.hart == 0
                || attribution.hart_generation == 0
                || attribution.event == 0
                || attribution.generation == 0
            {
                return Err(SemanticInvariantError::HartEventAttributionInvalid {
                    attribution: attribution.id,
                });
            }
            let Some(hart) =
                self.domains.scheduler.harts.iter().find(|record| record.id == attribution.hart)
            else {
                return Err(SemanticInvariantError::HartEventAttributionMissingHart {
                    attribution: attribution.id,
                    hart: attribution.hart,
                });
            };
            if hart.generation < attribution.hart_generation
                || hart.hardware_id != attribution.hardware_hart
            {
                return Err(SemanticInvariantError::HartEventAttributionHartGenerationMismatch {
                    attribution: attribution.id,
                    hart: attribution.hart,
                });
            }
            let Some(event) =
                self.event_log.events.iter().find(|record| record.id == attribution.event)
            else {
                return Err(SemanticInvariantError::HartEventAttributionMissingEvent {
                    attribution: attribution.id,
                    event: attribution.event,
                });
            };
            if event.source != attribution.event_source {
                return Err(SemanticInvariantError::HartEventAttributionEventMismatch {
                    attribution: attribution.id,
                    event: attribution.event,
                });
            }
            match (attribution.activation, attribution.activation_generation) {
                (Some(activation), Some(generation)) => {
                    if !self
                        .domains
                        .scheduler
                        .runtime_activations
                        .iter()
                        .any(|record| record.id == activation && record.generation >= generation)
                    {
                        return Err(
                            SemanticInvariantError::HartEventAttributionActivationMismatch {
                                attribution: attribution.id,
                                activation,
                            },
                        );
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(SemanticInvariantError::HartEventAttributionActivationMismatch {
                        attribution: attribution.id,
                        activation: attribution.activation.unwrap_or(0),
                    });
                }
            }
        }
        Ok(())
    }
}
