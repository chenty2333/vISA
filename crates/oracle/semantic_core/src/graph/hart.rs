use super::*;

impl SemanticGraph {
    pub fn register_hart_with_id(
        &mut self,
        hart: HartId,
        hardware_id: u32,
        label: &str,
        boot: bool,
        note: &str,
    ) -> bool {
        if hart == 0
            || label.is_empty()
            || self
                .domains
                .scheduler
                .harts
                .iter()
                .any(|record| record.id == hart || record.hardware_id == hardware_id)
            || (boot && self.domains.scheduler.harts.iter().any(|record| record.boot))
        {
            return false;
        }
        let generation = 1;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartRegistered {
                hart,
                hardware_id,
                label: label.to_string(),
                boot,
                generation,
            },
        );
        self.domains.scheduler.harts.push(HartRecord {
            id: hart,
            hardware_id,
            label: label.to_string(),
            state: HartState::Created,
            generation,
            boot,
            current_activation: None,
            current_activation_generation: None,
            current_task: None,
            current_task_generation: None,
            current_store: None,
            current_store_generation: None,
            last_event: Some(event),
            last_current_event: None,
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            hart,
            generation,
            event,
            "HartRegistered",
            None,
            None,
            note,
        );
        true
    }

    pub fn set_hart_state(
        &mut self,
        hart: HartId,
        hart_generation: Generation,
        state: HartState,
        reason: &str,
        note: &str,
    ) -> bool {
        if reason.is_empty() {
            return false;
        }
        let Some(index) = self
            .domains
            .scheduler
            .harts
            .iter()
            .position(|record| record.id == hart && record.generation == hart_generation)
        else {
            return false;
        };
        let from = self.domains.scheduler.harts[index].state;
        if from == state {
            return false;
        }
        self.domains.scheduler.harts[index].state = state;
        self.domains.scheduler.harts[index].generation += 1;
        if !note.is_empty() {
            self.domains.scheduler.harts[index].note = note.to_string();
        }
        let generation = self.domains.scheduler.harts[index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartStateChanged {
                hart,
                from,
                to: state,
                reason: reason.to_string(),
                generation,
            },
        );
        self.domains.scheduler.harts[index].last_event = Some(event);
        let current_activation = self.domains.scheduler.harts[index].current_activation;
        let current_activation_generation =
            self.domains.scheduler.harts[index].current_activation_generation;
        let _ = self.push_hart_event_attribution(
            hart,
            generation,
            event,
            "HartStateChanged",
            current_activation,
            current_activation_generation,
            note,
        );
        true
    }

    pub fn bind_hart_current_activation(
        &mut self,
        hart: HartId,
        hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        note: &str,
    ) -> bool {
        let Some(hart_index) = self
            .domains
            .scheduler
            .harts
            .iter()
            .position(|record| record.id == hart && record.generation == hart_generation)
        else {
            return false;
        };
        if self.domains.scheduler.harts[hart_index].state != HartState::Idle
            || self.domains.scheduler.harts[hart_index].current_activation.is_some()
        {
            return false;
        }
        if self.domains.scheduler.harts.iter().any(|record| {
            record.id != hart
                && record.current_activation == Some(activation)
                && record.current_activation_generation == Some(activation_generation)
        }) {
            return false;
        }
        let Some(activation_record) =
            self.domains.scheduler.runtime_activations.iter().find(|record| {
                record.id == activation
                    && record.generation == activation_generation
                    && record.state == RuntimeActivationState::Running
            })
        else {
            return false;
        };
        if !self.domains.scheduler.tasks.iter().any(|task| {
            task.id == activation_record.owner_task
                && task.generation == activation_record.owner_task_generation
        }) {
            return false;
        }
        if let Some(store) = activation_record.owner_store {
            let Some(generation) = activation_record.owner_store_generation else {
                return false;
            };
            if !self.domains.lifecycle.stores.iter().any(|store_record| {
                store_record.id == store
                    && store_record.generation == generation
                    && store_record.state != StoreState::Dead
            }) {
                return false;
            }
        }

        let from = self.domains.scheduler.harts[hart_index].state;
        self.domains.scheduler.harts[hart_index].state = HartState::Running;
        self.domains.scheduler.harts[hart_index].generation += 1;
        self.domains.scheduler.harts[hart_index].current_activation = Some(activation);
        self.domains.scheduler.harts[hart_index].current_activation_generation =
            Some(activation_generation);
        self.domains.scheduler.harts[hart_index].current_task = Some(activation_record.owner_task);
        self.domains.scheduler.harts[hart_index].current_task_generation =
            Some(activation_record.owner_task_generation);
        self.domains.scheduler.harts[hart_index].current_store = activation_record.owner_store;
        self.domains.scheduler.harts[hart_index].current_store_generation =
            activation_record.owner_store_generation;
        if !note.is_empty() {
            self.domains.scheduler.harts[hart_index].note = note.to_string();
        }
        let generation = self.domains.scheduler.harts[hart_index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartCurrentActivationBound {
                hart,
                from,
                activation,
                activation_generation,
                generation,
            },
        );
        self.domains.scheduler.harts[hart_index].last_event = Some(event);
        self.domains.scheduler.harts[hart_index].last_current_event = Some(event);
        let _ = self.push_hart_event_attribution(
            hart,
            generation,
            event,
            "HartCurrentActivationBound",
            Some(activation),
            Some(activation_generation),
            note,
        );
        true
    }

    pub fn clear_hart_current_activation(
        &mut self,
        hart: HartId,
        hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if reason.is_empty() {
            return false;
        }
        let Some(hart_index) = self
            .domains
            .scheduler
            .harts
            .iter()
            .position(|record| record.id == hart && record.generation == hart_generation)
        else {
            return false;
        };
        if self.domains.scheduler.harts[hart_index].current_activation != Some(activation)
            || self.domains.scheduler.harts[hart_index].current_activation_generation
                != Some(activation_generation)
        {
            return false;
        }
        self.domains.scheduler.harts[hart_index].state = HartState::Idle;
        self.domains.scheduler.harts[hart_index].generation += 1;
        self.domains.scheduler.harts[hart_index].current_activation = None;
        self.domains.scheduler.harts[hart_index].current_activation_generation = None;
        self.domains.scheduler.harts[hart_index].current_task = None;
        self.domains.scheduler.harts[hart_index].current_task_generation = None;
        self.domains.scheduler.harts[hart_index].current_store = None;
        self.domains.scheduler.harts[hart_index].current_store_generation = None;
        if !note.is_empty() {
            self.domains.scheduler.harts[hart_index].note = note.to_string();
        }
        let generation = self.domains.scheduler.harts[hart_index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartCurrentActivationCleared {
                hart,
                activation,
                activation_generation,
                reason: reason.to_string(),
                generation,
            },
        );
        self.domains.scheduler.harts[hart_index].last_event = Some(event);
        self.domains.scheduler.harts[hart_index].last_current_event = Some(event);
        let _ = self.push_hart_event_attribution(
            hart,
            generation,
            event,
            "HartCurrentActivationCleared",
            Some(activation),
            Some(activation_generation),
            note,
        );
        true
    }

    pub fn harts(&self) -> &[HartRecord] {
        &self.domains.scheduler.harts
    }

    pub fn hart_count(&self) -> usize {
        self.domains.scheduler.harts.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_hart_generation_for_test(
        &mut self,
        hart: HartId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.scheduler.harts.iter_mut().find(|record| record.id == hart)
        {
            record.generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_hart_for_test(&mut self, hart: HartRecord) {
        self.domains.scheduler.harts.push(hart);
    }

    #[cfg(test)]
    pub(crate) fn corrupt_hart_current_activation_generation_for_test(
        &mut self,
        hart: HartId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.scheduler.harts.iter_mut().find(|record| record.id == hart)
        {
            record.current_activation_generation = Some(generation);
        }
    }

    pub fn check_hart_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut boot_harts = 0;
        for (index, hart) in self.domains.scheduler.harts.iter().enumerate() {
            if hart.id == 0 || hart.generation == 0 || hart.label.is_empty() {
                return Err(SemanticInvariantError::HartInvalidObjectIdentity { hart: hart.id });
            }
            if hart.boot {
                boot_harts += 1;
            }
            match (
                hart.current_activation,
                hart.current_activation_generation,
                hart.current_task,
                hart.current_task_generation,
                hart.current_store,
                hart.current_store_generation,
            ) {
                (
                    Some(activation),
                    Some(activation_generation),
                    Some(task),
                    Some(task_generation),
                    store,
                    store_generation,
                ) => {
                    if hart.state != HartState::Running {
                        return Err(SemanticInvariantError::HartInactiveOwnsCurrentActivation {
                            hart: hart.id,
                            activation,
                        });
                    }
                    let Some(activation_record) =
                        self.domains.scheduler.runtime_activations.iter().find(|record| {
                            record.id == activation
                                && record.generation == activation_generation
                                && record.state == RuntimeActivationState::Running
                        })
                    else {
                        return Err(SemanticInvariantError::HartCurrentActivationMissing {
                            hart: hart.id,
                            activation,
                        });
                    };
                    if activation_record.owner_task != task
                        || activation_record.owner_task_generation != task_generation
                    {
                        return Err(SemanticInvariantError::HartCurrentTaskMismatch {
                            hart: hart.id,
                            activation,
                        });
                    }
                    if activation_record.owner_store != store
                        || activation_record.owner_store_generation != store_generation
                    {
                        return Err(SemanticInvariantError::HartCurrentStoreMismatch {
                            hart: hart.id,
                            activation,
                        });
                    }
                }
                (None, None, None, None, None, None) => {
                    if hart.state == HartState::Running {
                        return Err(SemanticInvariantError::HartRunningWithoutCurrentActivation {
                            hart: hart.id,
                        });
                    }
                }
                _ => {
                    return Err(SemanticInvariantError::HartCurrentActivationGenerationMissing {
                        hart: hart.id,
                    });
                }
            }
            if self.domains.scheduler.harts[index + 1..].iter().any(|other| other.id == hart.id) {
                return Err(SemanticInvariantError::DuplicateHart { hart: hart.id });
            }
            if let (Some(activation), Some(activation_generation)) =
                (hart.current_activation, hart.current_activation_generation)
            {
                if let Some(other) =
                    self.domains.scheduler.harts[index + 1..].iter().find(|other| {
                        other.current_activation == Some(activation)
                            && other.current_activation_generation == Some(activation_generation)
                    })
                {
                    return Err(SemanticInvariantError::ActivationCurrentOnMultipleHarts {
                        activation,
                        first_hart: hart.id,
                        second_hart: other.id,
                    });
                }
            }
            if self.domains.scheduler.harts[index + 1..]
                .iter()
                .any(|other| other.hardware_id == hart.hardware_id)
            {
                return Err(SemanticInvariantError::DuplicateHardwareHart {
                    hardware_id: hart.hardware_id,
                });
            }
        }
        if boot_harts > 1 {
            return Err(SemanticInvariantError::MultipleBootHarts);
        }
        Ok(())
    }
}
