use super::*;

impl SemanticGraph {
    pub fn create_activation_context(
        &mut self,
        activation: ActivationId,
        activation_generation: Generation,
    ) -> ActivationContextId {
        let context = self.next_activation_context_id;
        self.next_activation_context_id += 1;
        self.create_activation_context_with_id(context, activation, activation_generation);
        context
    }

    pub fn create_activation_context_with_id(
        &mut self,
        context: ActivationContextId,
        activation: ActivationId,
        activation_generation: Generation,
    ) -> bool {
        if context == 0
            || self
                .activation_contexts
                .iter()
                .any(|record| record.id == context)
        {
            return false;
        }
        let Some(activation_record) = self
            .runtime_activations
            .iter()
            .find(|record| record.id == activation && record.generation == activation_generation)
        else {
            return false;
        };
        if matches!(
            activation_record.state,
            RuntimeActivationState::Dead | RuntimeActivationState::Exited
        ) {
            return false;
        }
        if self.activation_contexts.iter().any(|record| {
            record.activation == activation && record.state != ActivationContextState::Dropped
        }) {
            return false;
        }
        if !self.tasks.iter().any(|task| {
            task.id == activation_record.owner_task
                && task.generation == activation_record.owner_task_generation
        }) {
            return false;
        }
        if let Some(store) = activation_record.owner_store {
            let Some(generation) = activation_record.owner_store_generation else {
                return false;
            };
            if !self.stores.iter().any(|record| {
                record.id == store
                    && record.generation == generation
                    && record.state != StoreState::Dead
            }) {
                return false;
            }
        }

        self.next_activation_context_id = self.next_activation_context_id.max(context + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::ActivationContextCreated {
                context,
                activation,
                activation_generation,
                generation: 1,
            },
        );
        self.activation_contexts.push(ActivationContextRecord {
            id: context,
            activation,
            activation_generation,
            owner_task: activation_record.owner_task,
            owner_task_generation: activation_record.owner_task_generation,
            owner_store: activation_record.owner_store,
            owner_store_generation: activation_record.owner_store_generation,
            generation: 1,
            state: ActivationContextState::Created,
            current_saved_context: None,
            current_saved_context_generation: None,
            last_event: Some(event),
        });
        true
    }

    pub fn capture_saved_context_with_id(
        &mut self,
        saved_context: SavedContextId,
        context: ActivationContextId,
        context_generation: Generation,
        reason: SavedContextReason,
        pc: u64,
        sp: u64,
        flags: u64,
        note: &str,
    ) -> bool {
        if saved_context == 0
            || self
                .saved_contexts
                .iter()
                .any(|record| record.id == saved_context)
        {
            return false;
        }
        let Some(context_index) = self
            .activation_contexts
            .iter()
            .position(|record| record.id == context && record.generation == context_generation)
        else {
            return false;
        };
        if self.activation_contexts[context_index].state == ActivationContextState::Dropped {
            return false;
        }
        if self.activation_contexts[context_index]
            .current_saved_context
            .is_some()
        {
            return false;
        }
        let activation = self.activation_contexts[context_index].activation;
        let activation_generation = self.activation_contexts[context_index].activation_generation;
        let Some(activation_record) = self
            .runtime_activations
            .iter()
            .find(|record| record.id == activation && record.generation == activation_generation)
        else {
            return false;
        };
        if matches!(
            activation_record.state,
            RuntimeActivationState::Dead | RuntimeActivationState::Exited
        ) {
            return false;
        }

        self.next_saved_context_id = self.next_saved_context_id.max(saved_context + 1);
        self.activation_contexts[context_index].generation += 1;
        self.activation_contexts[context_index].state = ActivationContextState::Saved;
        self.activation_contexts[context_index].current_saved_context = Some(saved_context);
        self.activation_contexts[context_index].current_saved_context_generation = Some(1);
        let updated_context_generation = self.activation_contexts[context_index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::SavedContextCaptured {
                saved_context,
                context,
                context_generation: updated_context_generation,
                activation,
                activation_generation,
                reason,
                generation: 1,
            },
        );
        self.activation_contexts[context_index].last_event = Some(event);
        self.saved_contexts.push(SavedContextRecord {
            id: saved_context,
            context,
            context_generation: updated_context_generation,
            activation,
            activation_generation,
            owner_task: self.activation_contexts[context_index].owner_task,
            owner_task_generation: self.activation_contexts[context_index].owner_task_generation,
            source_preemption: None,
            source_preemption_generation: None,
            generation: 1,
            state: SavedContextState::Captured,
            reason,
            pc,
            sp,
            flags,
            integer_registers: 33,
            saved_at_event: event,
            note: note.to_string(),
        });
        true
    }

    pub fn save_preempted_context_with_ids(
        &mut self,
        context: ActivationContextId,
        saved_context: SavedContextId,
        preemption: PreemptionId,
        preemption_generation: Generation,
        pc: u64,
        sp: u64,
        flags: u64,
        note: &str,
    ) -> bool {
        if context == 0
            || saved_context == 0
            || pc == 0
            || sp == 0
            || self
                .activation_contexts
                .iter()
                .any(|record| record.id == context)
            || self
                .saved_contexts
                .iter()
                .any(|record| record.id == saved_context)
        {
            return false;
        }
        let Some(preemption_record) = self.preemptions.iter().find(|record| {
            record.id == preemption
                && record.generation == preemption_generation
                && record.state == PreemptionState::Applied
        }) else {
            return false;
        };
        let activation = preemption_record.activation;
        let activation_generation = preemption_record.activation_generation_after;
        let Some(activation_record) = self
            .runtime_activations
            .iter()
            .find(|record| record.id == activation && record.generation == activation_generation)
        else {
            return false;
        };
        if matches!(
            activation_record.state,
            RuntimeActivationState::Dead | RuntimeActivationState::Exited
        ) {
            return false;
        }
        if self.activation_contexts.iter().any(|record| {
            record.activation == activation && record.state != ActivationContextState::Dropped
        }) {
            return false;
        }
        if !self.tasks.iter().any(|task| {
            task.id == activation_record.owner_task
                && task.generation == activation_record.owner_task_generation
        }) {
            return false;
        }
        if let Some(store) = activation_record.owner_store {
            let Some(generation) = activation_record.owner_store_generation else {
                return false;
            };
            if !self.stores.iter().any(|record| {
                record.id == store
                    && record.generation == generation
                    && record.state != StoreState::Dead
            }) {
                return false;
            }
        }

        let owner_task = activation_record.owner_task;
        let owner_task_generation = activation_record.owner_task_generation;
        let owner_store = activation_record.owner_store;
        let owner_store_generation = activation_record.owner_store_generation;

        self.next_activation_context_id = self.next_activation_context_id.max(context + 1);
        let created_event = self.event_log.push(
            "scheduler",
            EventKind::ActivationContextCreated {
                context,
                activation,
                activation_generation,
                generation: 1,
            },
        );
        self.activation_contexts.push(ActivationContextRecord {
            id: context,
            activation,
            activation_generation,
            owner_task,
            owner_task_generation,
            owner_store,
            owner_store_generation,
            generation: 1,
            state: ActivationContextState::Created,
            current_saved_context: None,
            current_saved_context_generation: None,
            last_event: Some(created_event),
        });

        let context_index = self.activation_contexts.len() - 1;
        self.next_saved_context_id = self.next_saved_context_id.max(saved_context + 1);
        self.activation_contexts[context_index].generation += 1;
        self.activation_contexts[context_index].state = ActivationContextState::Saved;
        self.activation_contexts[context_index].current_saved_context = Some(saved_context);
        self.activation_contexts[context_index].current_saved_context_generation = Some(1);
        let updated_context_generation = self.activation_contexts[context_index].generation;
        let saved_event = self.event_log.push(
            "scheduler",
            EventKind::SavedContextCaptured {
                saved_context,
                context,
                context_generation: updated_context_generation,
                activation,
                activation_generation,
                reason: SavedContextReason::TimerPreempt,
                generation: 1,
            },
        );
        self.activation_contexts[context_index].last_event = Some(saved_event);
        self.saved_contexts.push(SavedContextRecord {
            id: saved_context,
            context,
            context_generation: updated_context_generation,
            activation,
            activation_generation,
            owner_task,
            owner_task_generation,
            source_preemption: Some(preemption),
            source_preemption_generation: Some(preemption_generation),
            generation: 1,
            state: SavedContextState::Captured,
            reason: SavedContextReason::TimerPreempt,
            pc,
            sp,
            flags,
            integer_registers: 33,
            saved_at_event: saved_event,
            note: note.to_string(),
        });
        true
    }

    pub fn activation_contexts(&self) -> &[ActivationContextRecord] {
        &self.activation_contexts
    }

    pub fn saved_contexts(&self) -> &[SavedContextRecord] {
        &self.saved_contexts
    }

    pub fn activation_context_count(&self) -> usize {
        self.activation_contexts.len()
    }

    pub fn saved_context_count(&self) -> usize {
        self.saved_contexts.len()
    }

    #[cfg(test)]
    pub(crate) fn clear_activation_context_saved_ref_for_test(
        &mut self,
        context: ActivationContextId,
    ) {
        if let Some(record) = self
            .activation_contexts
            .iter_mut()
            .find(|record| record.id == context)
        {
            record.current_saved_context_generation = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn clear_saved_context_source_preemption_generation_for_test(
        &mut self,
        saved_context: SavedContextId,
    ) {
        if let Some(record) = self
            .saved_contexts
            .iter_mut()
            .find(|record| record.id == saved_context)
        {
            record.source_preemption_generation = None;
        }
    }

    pub fn check_context_invariants(&self) -> Result<(), SemanticInvariantError> {
        for context in &self.activation_contexts {
            let Some(activation) = self.runtime_activations.iter().find(|activation| {
                activation.id == context.activation
                    && (activation.generation == context.activation_generation
                        || (context.state == ActivationContextState::Dropped
                            && activation.generation >= context.activation_generation))
            }) else {
                return Err(SemanticInvariantError::ActivationContextMissingActivation {
                    context: context.id,
                    activation: context.activation,
                });
            };
            if context.state == ActivationContextState::Dropped {
                continue;
            }
            if context.state != ActivationContextState::Dropped
                && matches!(
                    activation.state,
                    RuntimeActivationState::Dead | RuntimeActivationState::Exited
                )
            {
                return Err(SemanticInvariantError::DeadActivationOwnsLiveContext {
                    activation: activation.id,
                    context: context.id,
                });
            }
            if !self.tasks.iter().any(|task| {
                task.id == context.owner_task && task.generation == context.owner_task_generation
            }) {
                return Err(SemanticInvariantError::ActivationContextMissingTask {
                    context: context.id,
                    task: context.owner_task,
                });
            }
            if let Some(store) = context.owner_store {
                let Some(generation) = context.owner_store_generation else {
                    return Err(SemanticInvariantError::ActivationContextMissingStore {
                        context: context.id,
                        store,
                    });
                };
                if !self.stores.iter().any(|record| {
                    record.id == store
                        && record.generation == generation
                        && record.state != StoreState::Dead
                }) {
                    return Err(SemanticInvariantError::ActivationContextMissingStore {
                        context: context.id,
                        store,
                    });
                }
            }
            if let Some(saved) = context.current_saved_context {
                let Some(saved_generation) = context.current_saved_context_generation else {
                    return Err(
                        SemanticInvariantError::ActivationContextSavedGenerationMissing {
                            context: context.id,
                            saved_context: saved,
                        },
                    );
                };
                let Some(saved_record) = self
                    .saved_contexts
                    .iter()
                    .find(|record| record.id == saved && record.generation == saved_generation)
                else {
                    return Err(
                        SemanticInvariantError::ActivationContextMissingSavedContext {
                            context: context.id,
                            saved_context: saved,
                        },
                    );
                };
                if saved_record.context != context.id
                    || saved_record.context_generation != context.generation
                    || saved_record.activation != context.activation
                    || saved_record.activation_generation != context.activation_generation
                {
                    return Err(
                        SemanticInvariantError::ActivationContextSavedContextMismatch {
                            context: context.id,
                            saved_context: saved,
                        },
                    );
                }
            }
        }

        for activation in &self.runtime_activations {
            let live_contexts = self
                .activation_contexts
                .iter()
                .filter(|context| {
                    context.activation == activation.id
                        && context.state != ActivationContextState::Dropped
                })
                .count();
            if live_contexts > 1 {
                return Err(SemanticInvariantError::ActivationHasMultipleLiveContexts {
                    activation: activation.id,
                    contexts: live_contexts,
                });
            }
        }

        for saved in &self.saved_contexts {
            if saved.pc == 0 || saved.sp == 0 {
                return Err(SemanticInvariantError::SavedContextMachineFrameMissing {
                    saved_context: saved.id,
                });
            }
            let historical_saved = matches!(
                saved.state,
                SavedContextState::Restored
                    | SavedContextState::Superseded
                    | SavedContextState::Dropped
            );
            let context_exists = if historical_saved {
                self.activation_contexts.iter().any(|context| {
                    context.id == saved.context && context.generation >= saved.context_generation
                })
            } else {
                self.activation_contexts.iter().any(|context| {
                    context.id == saved.context && context.generation == saved.context_generation
                })
            };
            if !context_exists {
                return Err(SemanticInvariantError::SavedContextMissingContext {
                    saved_context: saved.id,
                    context: saved.context,
                });
            }
            let activation_exists = if historical_saved {
                self.runtime_activations.iter().any(|activation| {
                    activation.id == saved.activation
                        && activation.generation >= saved.activation_generation
                })
            } else {
                self.runtime_activations.iter().any(|activation| {
                    activation.id == saved.activation
                        && activation.generation == saved.activation_generation
                })
            };
            if !activation_exists {
                return Err(SemanticInvariantError::SavedContextMissingActivation {
                    saved_context: saved.id,
                    activation: saved.activation,
                });
            }
            let saved_task_exists = if historical_saved {
                self.tasks.iter().any(|task| {
                    task.id == saved.owner_task && task.generation >= saved.owner_task_generation
                })
            } else {
                self.tasks.iter().any(|task| {
                    task.id == saved.owner_task && task.generation == saved.owner_task_generation
                })
            };
            if !saved_task_exists {
                return Err(SemanticInvariantError::SavedContextMissingTask {
                    saved_context: saved.id,
                    task: saved.owner_task,
                });
            }
            match (saved.source_preemption, saved.source_preemption_generation) {
                (Some(preemption), Some(generation)) => {
                    let Some(preemption_record) = self
                        .preemptions
                        .iter()
                        .find(|record| record.id == preemption && record.generation == generation)
                    else {
                        return Err(SemanticInvariantError::SavedContextMissingPreemption {
                            saved_context: saved.id,
                            preemption,
                        });
                    };
                    if preemption_record.activation != saved.activation
                        || preemption_record.activation_generation_after
                            != saved.activation_generation
                    {
                        return Err(SemanticInvariantError::SavedContextPreemptionMismatch {
                            saved_context: saved.id,
                            preemption,
                        });
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(
                        SemanticInvariantError::SavedContextMissingPreemptionGeneration {
                            saved_context: saved.id,
                        },
                    );
                }
            }
        }

        Ok(())
    }
}
