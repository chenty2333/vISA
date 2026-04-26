use super::*;

impl SemanticGraph {
    pub fn create_runtime_activation(
        &mut self,
        owner_task: TaskId,
        owner_task_generation: Generation,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        code_object: Option<ContractObjectRef>,
    ) -> ActivationId {
        let activation = self.next_runtime_activation_id;
        self.next_runtime_activation_id += 1;
        self.create_runtime_activation_with_id(
            activation,
            owner_task,
            owner_task_generation,
            owner_store,
            owner_store_generation,
            code_object,
        );
        activation
    }

    pub fn create_runtime_activation_with_id(
        &mut self,
        activation: ActivationId,
        owner_task: TaskId,
        owner_task_generation: Generation,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        code_object: Option<ContractObjectRef>,
    ) -> bool {
        if activation == 0
            || self
                .runtime_activations
                .iter()
                .any(|record| record.id == activation)
            || !self
                .tasks
                .iter()
                .any(|task| task.id == owner_task && task.generation == owner_task_generation)
        {
            return false;
        }
        if let Some(code) = code_object
            && code.kind != ContractObjectKind::CodeObject
        {
            return false;
        }
        match (owner_store, owner_store_generation) {
            (Some(store), Some(generation)) => {
                if !self.stores.iter().any(|record| {
                    record.id == store
                        && record.generation == generation
                        && record.state != StoreState::Dead
                }) {
                    return false;
                }
            }
            (Some(_), None) | (None, Some(_)) => return false,
            (None, None) => {}
        }
        self.next_runtime_activation_id = self.next_runtime_activation_id.max(activation + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationCreated {
                activation,
                task: owner_task,
                generation: 1,
            },
        );
        self.runtime_activations.push(RuntimeActivationRecord {
            id: activation,
            owner_task,
            owner_task_generation,
            owner_store,
            owner_store_generation,
            code_object,
            generation: 1,
            state: RuntimeActivationState::Created,
            runnable_queue: None,
            runnable_queue_generation: None,
            last_event: Some(event),
        });
        true
    }

    pub fn create_runnable_queue(&mut self, label: &str) -> RunnableQueueId {
        let queue = self.next_runnable_queue_id;
        self.next_runnable_queue_id += 1;
        self.create_runnable_queue_with_id(queue, label);
        queue
    }

    pub fn create_runnable_queue_with_id(&mut self, queue: RunnableQueueId, label: &str) -> bool {
        if queue == 0 || self.runnable_queues.iter().any(|record| record.id == queue) {
            return false;
        }
        self.next_runnable_queue_id = self.next_runnable_queue_id.max(queue + 1);
        self.runnable_queues.push(RunnableQueueRecord {
            id: queue,
            label: label.to_string(),
            generation: 1,
            state: RunnableQueueState::Active,
            entries: Vec::new(),
        });
        self.event_log.push(
            "scheduler",
            EventKind::RunnableQueueCreated {
                queue,
                label: label.to_string(),
                generation: 1,
            },
        );
        true
    }

    pub fn enqueue_runnable_activation(
        &mut self,
        queue: RunnableQueueId,
        activation: ActivationId,
        expected_generation: Generation,
    ) -> bool {
        let Some(queue_index) = self
            .runnable_queues
            .iter()
            .position(|record| record.id == queue && record.state == RunnableQueueState::Active)
        else {
            return false;
        };
        if self.runnable_queues[queue_index]
            .entries
            .iter()
            .any(|entry| entry.activation == activation)
        {
            return false;
        }
        if self.runnable_queues.iter().any(|record| {
            record
                .entries
                .iter()
                .any(|entry| entry.activation == activation)
        }) {
            return false;
        }
        let Some(activation_index) = self
            .runtime_activations
            .iter()
            .position(|record| record.id == activation)
        else {
            return false;
        };
        if self.runtime_activations[activation_index].generation != expected_generation {
            return false;
        }
        if !matches!(
            self.runtime_activations[activation_index].state,
            RuntimeActivationState::Created | RuntimeActivationState::Blocked
        ) {
            return false;
        }
        if self.runtime_activations[activation_index]
            .runnable_queue
            .is_some()
        {
            return false;
        }
        let owner_task = self.runtime_activations[activation_index].owner_task;
        let owner_task_generation =
            self.runtime_activations[activation_index].owner_task_generation;
        let Some(owner_task) = self
            .tasks
            .iter()
            .find(|task| task.id == owner_task && task.generation == owner_task_generation)
        else {
            return false;
        };
        if owner_task.state == TaskState::Pending {
            return false;
        }
        if let Some(store) = self.runtime_activations[activation_index].owner_store {
            let Some(generation) =
                self.runtime_activations[activation_index].owner_store_generation
            else {
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

        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Runnable;
        self.runtime_activations[activation_index].generation += 1;
        self.runtime_activations[activation_index].runnable_queue = Some(queue);
        self.runtime_activations[activation_index].runnable_queue_generation =
            Some(self.runnable_queues[queue_index].generation);
        let generation = self.runtime_activations[activation_index].generation;
        self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Runnable,
                generation,
            },
        );
        let queued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableQueued {
                queue,
                activation,
                activation_generation: generation,
            },
        );
        self.runtime_activations[activation_index].last_event = Some(queued_event);
        self.runnable_queues[queue_index]
            .entries
            .push(RunnableQueueEntry {
                activation,
                activation_generation: generation,
                enqueued_at: queued_event,
            });
        true
    }

    pub fn dequeue_runnable_activation(
        &mut self,
        queue: RunnableQueueId,
        activation: ActivationId,
    ) -> bool {
        let Some(queue_index) = self
            .runnable_queues
            .iter()
            .position(|record| record.id == queue && record.state == RunnableQueueState::Active)
        else {
            return false;
        };
        let Some(entry_index) = self.runnable_queues[queue_index]
            .entries
            .iter()
            .position(|entry| entry.activation == activation)
        else {
            return false;
        };
        let entry = self.runnable_queues[queue_index].entries[entry_index].clone();
        let Some(activation_index) = self
            .runtime_activations
            .iter()
            .position(|record| record.id == activation)
        else {
            return false;
        };
        if self.runtime_activations[activation_index].generation != entry.activation_generation
            || self.runtime_activations[activation_index].state != RuntimeActivationState::Runnable
        {
            return false;
        }
        self.runnable_queues[queue_index]
            .entries
            .remove(entry_index);
        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Running;
        self.runtime_activations[activation_index].generation += 1;
        self.runtime_activations[activation_index].runnable_queue = None;
        self.runtime_activations[activation_index].runnable_queue_generation = None;
        let generation = self.runtime_activations[activation_index].generation;
        let dequeued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableDequeued {
                queue,
                activation,
                activation_generation: entry.activation_generation,
            },
        );
        let state_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Running,
                generation,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(state_event.max(dequeued_event));
        true
    }

    pub fn runtime_activations(&self) -> &[RuntimeActivationRecord] {
        &self.runtime_activations
    }

    pub fn runnable_queues(&self) -> &[RunnableQueueRecord] {
        &self.runnable_queues
    }

    pub fn runtime_activation_count(&self) -> usize {
        self.runtime_activations.len()
    }

    pub fn runnable_queue_count(&self) -> usize {
        self.runnable_queues.len()
    }

    #[cfg(test)]
    pub(crate) fn clear_runtime_activation_queue_for_test(&mut self, activation: ActivationId) {
        if let Some(record) = self
            .runtime_activations
            .iter_mut()
            .find(|record| record.id == activation)
        {
            record.runnable_queue = None;
            record.runnable_queue_generation = None;
        }
    }

    pub fn check_scheduler_invariants(&self) -> Result<(), SemanticInvariantError> {
        for activation in &self.runtime_activations {
            let Some(task) = self.tasks.iter().find(|task| {
                task.id == activation.owner_task
                    && task.generation == activation.owner_task_generation
            }) else {
                return Err(SemanticInvariantError::ActivationReferencesMissingTask {
                    activation: activation.id,
                    task: activation.owner_task,
                });
            };
            if let Some(store) = activation.owner_store {
                let Some(store_record) = self.stores.iter().find(|record| {
                    record.id == store
                        && activation.owner_store_generation == Some(record.generation)
                }) else {
                    return Err(SemanticInvariantError::ActivationReferencesMissingStore {
                        activation: activation.id,
                        store,
                    });
                };
                if store_record.state == StoreState::Dead
                    && activation.state != RuntimeActivationState::Dead
                {
                    return Err(SemanticInvariantError::DeadStoreOwnsLiveActivation {
                        store,
                        activation: activation.id,
                    });
                }
            }
            if task.state == TaskState::Pending
                && activation.state == RuntimeActivationState::Runnable
            {
                return Err(SemanticInvariantError::PendingTaskHasRunnableActivation {
                    task: task.id,
                    activation: activation.id,
                });
            }
        }

        for queue in &self.runnable_queues {
            if queue.state != RunnableQueueState::Active && !queue.entries.is_empty() {
                return Err(SemanticInvariantError::InactiveRunnableQueueHasEntries {
                    queue: queue.id,
                });
            }
            for entry in &queue.entries {
                let Some(activation) = self
                    .runtime_activations
                    .iter()
                    .find(|record| record.id == entry.activation)
                else {
                    return Err(
                        SemanticInvariantError::RunnableQueueReferencesMissingActivation {
                            queue: queue.id,
                            activation: entry.activation,
                        },
                    );
                };
                if activation.generation != entry.activation_generation {
                    return Err(
                        SemanticInvariantError::RunnableQueueActivationGenerationMismatch {
                            queue: queue.id,
                            activation: entry.activation,
                            expected: entry.activation_generation,
                            actual: activation.generation,
                        },
                    );
                }
                if activation.state != RuntimeActivationState::Runnable {
                    return Err(
                        SemanticInvariantError::RunnableQueueContainsNonRunnableActivation {
                            queue: queue.id,
                            activation: entry.activation,
                            state: activation.state,
                        },
                    );
                }
                if activation.runnable_queue != Some(queue.id)
                    || activation.runnable_queue_generation != Some(queue.generation)
                {
                    return Err(SemanticInvariantError::RunnableQueueOwnershipMismatch {
                        queue: queue.id,
                        activation: entry.activation,
                    });
                }
            }
        }

        for activation in &self.runtime_activations {
            if activation.state == RuntimeActivationState::Runnable {
                let queue_refs = self
                    .runnable_queues
                    .iter()
                    .filter(|queue| {
                        queue
                            .entries
                            .iter()
                            .any(|entry| entry.activation == activation.id)
                    })
                    .count();
                if queue_refs != 1 {
                    return Err(
                        SemanticInvariantError::RunnableActivationQueueCountMismatch {
                            activation: activation.id,
                            queue_refs,
                        },
                    );
                }
            }
            if activation.state == RuntimeActivationState::Running
                && self.runnable_queues.iter().any(|queue| {
                    queue
                        .entries
                        .iter()
                        .any(|entry| entry.activation == activation.id)
                })
            {
                return Err(SemanticInvariantError::RunningActivationStillQueued {
                    activation: activation.id,
                });
            }
        }

        Ok(())
    }
}
