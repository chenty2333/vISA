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
            vector_state: None,
            vector_status: ActivationVectorState::Absent,
            vector_state_event: None,
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
            vector_state: None,
            vector_status: ActivationVectorState::Absent,
            vector_saved_at_event: None,
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
            vector_state: None,
            vector_status: ActivationVectorState::Absent,
            vector_state_event: None,
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
            vector_state: None,
            vector_status: ActivationVectorState::Absent,
            vector_saved_at_event: None,
            saved_at_event: saved_event,
            note: note.to_string(),
        });
        true
    }

    pub(crate) fn validate_dirty_vector_state_preempt_save(
        &self,
        context: ActivationContextId,
        context_generation: Generation,
        saved_context: SavedContextId,
        saved_context_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        vector_state: ContractObjectRef,
    ) -> Result<(), &'static str> {
        let Some(context_record) = self.activation_contexts.iter().find(|record| {
            record.id == context
                && record.generation == context_generation
                && record.state == ActivationContextState::Saved
        }) else {
            return Err("saved activation context generation is missing");
        };
        if context_record.current_saved_context != Some(saved_context)
            || context_record.current_saved_context_generation != Some(saved_context_generation)
        {
            return Err("saved activation context does not reference saved context generation");
        }
        if context_record.vector_status != ActivationVectorState::Dirty
            || context_record.vector_state != Some(vector_state)
        {
            return Err("preempt vector save requires dirty activation vector state");
        }

        let Some(saved_record) = self.saved_contexts.iter().find(|record| {
            record.id == saved_context
                && record.generation == saved_context_generation
                && record.state == SavedContextState::Captured
        }) else {
            return Err("saved context generation is missing or not captured");
        };
        if saved_record.vector_state.is_some()
            || saved_record.vector_status != ActivationVectorState::Absent
            || saved_record.vector_saved_at_event.is_some()
        {
            return Err("saved context already carries vector state");
        }
        if saved_record.context != context
            || saved_record.context_generation != context_generation
            || saved_record.activation != context_record.activation
            || saved_record.activation_generation != context_record.activation_generation
        {
            return Err("saved context does not match activation context generation");
        }
        if saved_record.source_preemption != Some(preemption)
            || saved_record.source_preemption_generation != Some(preemption_generation)
        {
            return Err("saved context preemption generation mismatch");
        }

        let Some(preemption_record) = self.preemptions.iter().find(|record| {
            record.id == preemption
                && record.generation == preemption_generation
                && record.state == PreemptionState::Applied
        }) else {
            return Err("preemption generation is missing");
        };
        if preemption_record.activation != context_record.activation
            || preemption_record.activation_generation_after != context_record.activation_generation
            || preemption_record.activation != saved_record.activation
            || preemption_record.activation_generation_after != saved_record.activation_generation
        {
            return Err("preempt vector save activation generation mismatch");
        }

        self.validate_activation_context_vector_state(
            context,
            context_generation,
            Some(vector_state),
            ActivationVectorState::Dirty,
        )
    }

    pub fn save_dirty_vector_state_on_preempt(
        &mut self,
        context: ActivationContextId,
        context_generation: Generation,
        saved_context: SavedContextId,
        saved_context_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        vector_state: ContractObjectRef,
        _note: &str,
    ) -> bool {
        if self
            .validate_dirty_vector_state_preempt_save(
                context,
                context_generation,
                saved_context,
                saved_context_generation,
                preemption,
                preemption_generation,
                vector_state,
            )
            .is_err()
        {
            return false;
        }
        let Some(context_index) = self.activation_contexts.iter().position(|record| {
            record.id == context
                && record.generation == context_generation
                && record.state == ActivationContextState::Saved
        }) else {
            return false;
        };
        let Some(saved_index) = self.saved_contexts.iter().position(|record| {
            record.id == saved_context
                && record.generation == saved_context_generation
                && record.state == SavedContextState::Captured
        }) else {
            return false;
        };

        let context_generation_before = self.activation_contexts[context_index].generation;
        self.activation_contexts[context_index].generation += 1;
        let context_generation_after = self.activation_contexts[context_index].generation;
        self.saved_contexts[saved_index].generation += 1;
        let saved_context_generation_after = self.saved_contexts[saved_index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::DirtyVectorStateSavedOnPreempt {
                saved_context,
                saved_context_generation: saved_context_generation_after,
                context,
                context_generation_before,
                context_generation_after,
                preemption,
                preemption_generation,
                vector_state,
                generation: 1,
            },
        );

        self.activation_contexts[context_index].vector_status = ActivationVectorState::Clean;
        self.activation_contexts[context_index].vector_state_event = Some(event);
        self.activation_contexts[context_index].last_event = Some(event);
        self.activation_contexts[context_index].current_saved_context_generation =
            Some(saved_context_generation_after);
        self.saved_contexts[saved_index].context_generation = context_generation_after;
        self.saved_contexts[saved_index].vector_state = Some(vector_state);
        self.saved_contexts[saved_index].vector_status = ActivationVectorState::Clean;
        self.saved_contexts[saved_index].vector_saved_at_event = Some(event);
        true
    }

    pub(crate) fn validate_activation_context_vector_state(
        &self,
        context: ActivationContextId,
        context_generation: Generation,
        vector_state: Option<ContractObjectRef>,
        vector_status: ActivationVectorState,
    ) -> Result<(), &'static str> {
        let Some(context_record) = self.activation_contexts.iter().find(|record| {
            record.id == context
                && record.generation == context_generation
                && record.state != ActivationContextState::Dropped
        }) else {
            return Err("activation context generation is missing or dropped");
        };

        match (vector_status.requires_vector_state(), vector_state) {
            (false, None) => Ok(()),
            (false, Some(_)) => Err("absent vector context cannot carry vector state"),
            (true, None) => Err("clean or dirty vector context requires vector state"),
            (true, Some(vector_ref)) => {
                if vector_ref.kind != ContractObjectKind::VectorState
                    || vector_ref.id == 0
                    || vector_ref.generation == 0
                {
                    return Err(
                        "activation context vector state must be an exact vector-state ref",
                    );
                }
                let Some(vector_record) = self.vector_states.iter().find(|record| {
                    record.id == vector_ref.id && record.generation == vector_ref.generation
                }) else {
                    return Err("activation context vector state is missing");
                };
                if !vector_record.state.is_live_owned() {
                    return Err("activation context vector state must be live-owned");
                }
                if vector_record.owner_activation
                    != ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        context_record.activation,
                        context_record.activation_generation,
                    )
                {
                    return Err("activation context vector state owner activation mismatch");
                }
                if let Some(store) = context_record.owner_store {
                    let Some(store_generation) = context_record.owner_store_generation else {
                        return Err("activation context vector state owner store mismatch");
                    };
                    if vector_record.owner_store
                        != ContractObjectRef::new(
                            ContractObjectKind::Store,
                            store,
                            store_generation,
                        )
                    {
                        return Err("activation context vector state owner store mismatch");
                    }
                }
                if let Some(activation) = self.runtime_activations.iter().find(|activation| {
                    activation.id == context_record.activation
                        && activation.generation == context_record.activation_generation
                }) {
                    if let Some(code_object) = activation.code_object
                        && vector_record.code_object != code_object
                    {
                        return Err("activation context vector state code object mismatch");
                    }
                }
                Ok(())
            }
        }
    }

    pub fn update_activation_context_vector_state(
        &mut self,
        context: ActivationContextId,
        context_generation: Generation,
        vector_state: Option<ContractObjectRef>,
        vector_status: ActivationVectorState,
        _note: &str,
    ) -> bool {
        if self
            .validate_activation_context_vector_state(
                context,
                context_generation,
                vector_state,
                vector_status,
            )
            .is_err()
        {
            return false;
        }
        let Some(index) = self
            .activation_contexts
            .iter()
            .position(|record| record.id == context && record.generation == context_generation)
        else {
            return false;
        };
        let context_generation_before = self.activation_contexts[index].generation;
        self.activation_contexts[index].generation += 1;
        let context_generation_after = self.activation_contexts[index].generation;
        let current_saved_context = self.activation_contexts[index].current_saved_context;
        let current_saved_context_generation =
            self.activation_contexts[index].current_saved_context_generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::ActivationContextVectorStateUpdated {
                context,
                context_generation_before,
                context_generation_after,
                vector_state,
                vector_status,
                generation: 1,
            },
        );
        self.activation_contexts[index].vector_state = vector_state;
        self.activation_contexts[index].vector_status = vector_status;
        self.activation_contexts[index].vector_state_event = Some(event);
        self.activation_contexts[index].last_event = Some(event);
        if let (Some(saved_context), Some(saved_context_generation)) =
            (current_saved_context, current_saved_context_generation)
            && let Some(saved) = self.saved_contexts.iter_mut().find(|record| {
                record.id == saved_context && record.generation == saved_context_generation
            })
        {
            saved.context_generation = context_generation_after;
        }
        true
    }

    pub(crate) fn validate_lazy_vector_state_enable(
        &self,
        context: ActivationContextId,
        context_generation: Generation,
        vector_state: ContractObjectRef,
    ) -> Result<(), &'static str> {
        let Some(context_record) = self.activation_contexts.iter().find(|record| {
            record.id == context
                && record.generation == context_generation
                && record.state != ActivationContextState::Dropped
        }) else {
            return Err("activation context generation is missing or dropped");
        };
        if context_record.vector_status != ActivationVectorState::Absent
            || context_record.vector_state.is_some()
        {
            return Err("lazy vector enable requires absent vector context");
        }
        self.validate_activation_context_vector_state(
            context,
            context_generation,
            Some(vector_state),
            ActivationVectorState::Dirty,
        )
    }

    pub fn enable_lazy_vector_state(
        &mut self,
        context: ActivationContextId,
        context_generation: Generation,
        vector_state: ContractObjectRef,
        _note: &str,
    ) -> bool {
        if self
            .validate_lazy_vector_state_enable(context, context_generation, vector_state)
            .is_err()
        {
            return false;
        }
        let Some(index) = self
            .activation_contexts
            .iter()
            .position(|record| record.id == context && record.generation == context_generation)
        else {
            return false;
        };
        let context_generation_before = self.activation_contexts[index].generation;
        self.activation_contexts[index].generation += 1;
        let context_generation_after = self.activation_contexts[index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::LazyVectorStateEnabled {
                context,
                context_generation_before,
                context_generation_after,
                vector_state,
                generation: 1,
            },
        );
        self.activation_contexts[index].vector_state = Some(vector_state);
        self.activation_contexts[index].vector_status = ActivationVectorState::Dirty;
        self.activation_contexts[index].vector_state_event = Some(event);
        self.activation_contexts[index].last_event = Some(event);
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

    #[cfg(test)]
    pub(crate) fn corrupt_activation_context_vector_state_generation_for_test(
        &mut self,
        context: ActivationContextId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .activation_contexts
            .iter_mut()
            .find(|record| record.id == context)
            && let Some(vector_state) = record.vector_state.as_mut()
        {
            vector_state.generation = generation;
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
            match (
                context.vector_status.requires_vector_state(),
                context.vector_state,
            ) {
                (false, None) => {}
                (false, Some(_)) => {
                    return Err(
                        SemanticInvariantError::ActivationContextVectorStateInvalid {
                            context: context.id,
                        },
                    );
                }
                (true, None) => {
                    return Err(
                        SemanticInvariantError::ActivationContextVectorStateMissing {
                            context: context.id,
                        },
                    );
                }
                (true, Some(vector_state)) => {
                    if vector_state.kind != ContractObjectKind::VectorState
                        || vector_state.id == 0
                        || vector_state.generation == 0
                    {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateInvalid {
                                context: context.id,
                            },
                        );
                    }
                    let Some(vector_record) = self.vector_states.iter().find(|record| {
                        record.id == vector_state.id && record.generation == vector_state.generation
                    }) else {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateMissing {
                                context: context.id,
                            },
                        );
                    };
                    if !vector_record.state.is_live_owned()
                        || vector_record.owner_activation
                            != ContractObjectRef::new(
                                ContractObjectKind::Activation,
                                context.activation,
                                context.activation_generation,
                            )
                    {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateInvalid {
                                context: context.id,
                            },
                        );
                    }
                    if let Some(store) = context.owner_store {
                        let Some(store_generation) = context.owner_store_generation else {
                            return Err(
                                SemanticInvariantError::ActivationContextVectorStateInvalid {
                                    context: context.id,
                                },
                            );
                        };
                        if vector_record.owner_store
                            != ContractObjectRef::new(
                                ContractObjectKind::Store,
                                store,
                                store_generation,
                            )
                        {
                            return Err(
                                SemanticInvariantError::ActivationContextVectorStateInvalid {
                                    context: context.id,
                                },
                            );
                        }
                    }
                    if let Some(code_object) = activation.code_object
                        && vector_record.code_object != code_object
                    {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateInvalid {
                                context: context.id,
                            },
                        );
                    }
                    let Some(vector_event) = context.vector_state_event else {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateMissing {
                                context: context.id,
                            },
                        );
                    };
                    if !self.event_log.events.iter().any(|event| {
                        if event.id != vector_event {
                            return false;
                        }
                        match &event.kind {
                            EventKind::ActivationContextVectorStateUpdated {
                                context: event_context,
                                context_generation_after,
                                vector_state: event_vector_state,
                                vector_status,
                                ..
                            } => {
                                *event_context == context.id
                                    && *context_generation_after <= context.generation
                                    && *event_vector_state == context.vector_state
                                    && *vector_status == context.vector_status
                            }
                            EventKind::LazyVectorStateEnabled {
                                context: event_context,
                                context_generation_after,
                                vector_state: event_vector_state,
                                ..
                            } => {
                                *event_context == context.id
                                    && *context_generation_after <= context.generation
                                    && Some(*event_vector_state) == context.vector_state
                                    && context.vector_status == ActivationVectorState::Dirty
                            }
                            EventKind::DirtyVectorStateSavedOnPreempt {
                                context: event_context,
                                context_generation_after,
                                vector_state: event_vector_state,
                                ..
                            } => {
                                *event_context == context.id
                                    && *context_generation_after <= context.generation
                                    && Some(*event_vector_state) == context.vector_state
                                    && context.vector_status == ActivationVectorState::Clean
                            }
                            _ => false,
                        }
                    }) {
                        return Err(
                            SemanticInvariantError::ActivationContextVectorStateMissing {
                                context: context.id,
                            },
                        );
                    }
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
            match (
                saved.vector_status.requires_vector_state(),
                saved.vector_state,
            ) {
                (false, None) => {}
                (false, Some(_)) | (true, None) => {
                    return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                        saved_context: saved.id,
                    });
                }
                (true, Some(vector_state)) => {
                    if vector_state.kind != ContractObjectKind::VectorState
                        || vector_state.id == 0
                        || vector_state.generation == 0
                    {
                        return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                            saved_context: saved.id,
                        });
                    }
                    let Some(vector_record) = self.vector_states.iter().find(|record| {
                        record.id == vector_state.id && record.generation == vector_state.generation
                    }) else {
                        return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                            saved_context: saved.id,
                        });
                    };
                    if vector_record.owner_activation
                        != ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            saved.activation,
                            saved.activation_generation,
                        )
                    {
                        return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                            saved_context: saved.id,
                        });
                    }
                    let Some(vector_event) = saved.vector_saved_at_event else {
                        return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                            saved_context: saved.id,
                        });
                    };
                    if !self.event_log.events.iter().any(|event| {
                        event.id == vector_event
                            && matches!(
                                &event.kind,
                                EventKind::DirtyVectorStateSavedOnPreempt {
                                    saved_context,
                                    saved_context_generation,
                                    context,
                                    context_generation_after,
                                    vector_state: event_vector_state,
                                    ..
                                } if *saved_context == saved.id
                                    && *saved_context_generation <= saved.generation
                                    && *context == saved.context
                                    && *context_generation_after <= saved.context_generation
                                    && *event_vector_state == vector_state
                            )
                    }) {
                        return Err(SemanticInvariantError::SavedContextVectorStateInvalid {
                            saved_context: saved.id,
                        });
                    }
                }
            }
        }

        Ok(())
    }
}
