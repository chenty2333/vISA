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

    pub fn preempt_running_activation_with_id(
        &mut self,
        preemption: PreemptionId,
        activation: ActivationId,
        activation_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        queue: RunnableQueueId,
        note: &str,
    ) -> bool {
        if preemption == 0
            || self
                .preemptions
                .iter()
                .any(|record| record.id == preemption)
        {
            return false;
        }
        let Some(queue_index) = self
            .runnable_queues
            .iter()
            .position(|record| record.id == queue && record.state == RunnableQueueState::Active)
        else {
            return false;
        };
        if self.runnable_queues.iter().any(|record| {
            record
                .entries
                .iter()
                .any(|entry| entry.activation == activation)
        }) {
            return false;
        }
        let Some(timer) = self.timer_interrupts.iter().find(|record| {
            record.id == timer_interrupt && record.generation == timer_interrupt_generation
        }) else {
            return false;
        };
        if timer.target_activation != Some(activation)
            || timer.target_activation_generation != Some(activation_generation)
        {
            return false;
        }
        let Some(activation_index) = self.runtime_activations.iter().position(|record| {
            record.id == activation
                && record.generation == activation_generation
                && record.state == RuntimeActivationState::Running
                && record.runnable_queue.is_none()
                && record.runnable_queue_generation.is_none()
        }) else {
            return false;
        };
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
        if matches!(
            owner_task.state,
            TaskState::Pending | TaskState::Cancelled | TaskState::Faulted | TaskState::Exited
        ) {
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

        self.next_preemption_id = self.next_preemption_id.max(preemption + 1);
        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Runnable;
        self.runtime_activations[activation_index].generation += 1;
        let to_generation = self.runtime_activations[activation_index].generation;
        let queue_generation = self.runnable_queues[queue_index].generation;
        self.runtime_activations[activation_index].runnable_queue = Some(queue);
        self.runtime_activations[activation_index].runnable_queue_generation =
            Some(queue_generation);

        let preempted_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationPreempted {
                preemption,
                activation,
                from_generation: activation_generation,
                to_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                queue_generation,
                generation: 1,
            },
        );
        let state_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Runnable,
                generation: to_generation,
            },
        );
        let queued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableQueued {
                queue,
                activation,
                activation_generation: to_generation,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(preempted_event.max(state_event).max(queued_event));
        self.runnable_queues[queue_index]
            .entries
            .push(RunnableQueueEntry {
                activation,
                activation_generation: to_generation,
                enqueued_at: queued_event,
            });
        self.preemptions.push(PreemptionRecord {
            id: preemption,
            activation,
            activation_generation_before: activation_generation,
            activation_generation_after: to_generation,
            timer_interrupt,
            timer_interrupt_generation,
            queue,
            queue_generation,
            generation: 1,
            state: PreemptionState::Applied,
            preempted_at_event: preempted_event,
            note: note.to_string(),
        });
        true
    }

    pub fn record_scheduler_decision_with_id(
        &mut self,
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        selected_activation: ActivationId,
        selected_activation_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if decision == 0
            || reason.is_empty()
            || self
                .scheduler_decisions
                .iter()
                .any(|record| record.id == decision)
        {
            return false;
        }
        let Some(queue_record) = self.runnable_queues.iter().find(|record| {
            record.id == queue
                && record.generation == queue_generation
                && record.state == RunnableQueueState::Active
        }) else {
            return false;
        };
        if !queue_record.entries.iter().any(|entry| {
            entry.activation == selected_activation
                && entry.activation_generation == selected_activation_generation
        }) {
            return false;
        }
        let Some(activation) = self.runtime_activations.iter().find(|record| {
            record.id == selected_activation
                && record.generation == selected_activation_generation
                && record.state == RuntimeActivationState::Runnable
                && record.runnable_queue == Some(queue)
                && record.runnable_queue_generation == Some(queue_generation)
        }) else {
            return false;
        };
        let owner_task = activation.owner_task;
        let owner_task_generation = activation.owner_task_generation;
        if !self
            .tasks
            .iter()
            .any(|task| task.id == owner_task && task.generation == owner_task_generation)
        {
            return false;
        }

        self.next_scheduler_decision_id = self.next_scheduler_decision_id.max(decision + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::SchedulerDecisionRecorded {
                decision,
                queue,
                queue_generation,
                activation: selected_activation,
                activation_generation: selected_activation_generation,
                generation: 1,
            },
        );
        self.scheduler_decisions.push(SchedulerDecisionRecord {
            id: decision,
            queue,
            queue_generation,
            selected_activation,
            selected_activation_generation,
            owner_task,
            owner_task_generation,
            generation: 1,
            state: SchedulerDecisionState::Recorded,
            decided_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        true
    }

    pub fn runtime_activations(&self) -> &[RuntimeActivationRecord] {
        &self.runtime_activations
    }

    pub fn runnable_queues(&self) -> &[RunnableQueueRecord] {
        &self.runnable_queues
    }

    pub fn preemptions(&self) -> &[PreemptionRecord] {
        &self.preemptions
    }

    pub fn scheduler_decisions(&self) -> &[SchedulerDecisionRecord] {
        &self.scheduler_decisions
    }

    pub fn runtime_activation_count(&self) -> usize {
        self.runtime_activations.len()
    }

    pub fn runnable_queue_count(&self) -> usize {
        self.runnable_queues.len()
    }

    pub fn preemption_count(&self) -> usize {
        self.preemptions.len()
    }

    pub fn scheduler_decision_count(&self) -> usize {
        self.scheduler_decisions.len()
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

    #[cfg(test)]
    pub(crate) fn corrupt_preemption_timer_generation_for_test(
        &mut self,
        preemption: PreemptionId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .preemptions
            .iter_mut()
            .find(|record| record.id == preemption)
        {
            record.timer_interrupt_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_scheduler_decision_activation_generation_for_test(
        &mut self,
        decision: SchedulerDecisionId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .scheduler_decisions
            .iter_mut()
            .find(|record| record.id == decision)
        {
            record.selected_activation_generation = generation;
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

        for preemption in &self.preemptions {
            let Some(timer) = self.timer_interrupts.iter().find(|record| {
                record.id == preemption.timer_interrupt
                    && record.generation == preemption.timer_interrupt_generation
            }) else {
                return Err(SemanticInvariantError::PreemptionMissingTimerInterrupt {
                    preemption: preemption.id,
                    interrupt: preemption.timer_interrupt,
                });
            };
            if timer.target_activation != Some(preemption.activation)
                || timer.target_activation_generation
                    != Some(preemption.activation_generation_before)
            {
                return Err(SemanticInvariantError::PreemptionTimerTargetMismatch {
                    preemption: preemption.id,
                    interrupt: preemption.timer_interrupt,
                    activation: preemption.activation,
                });
            }
            let Some(activation) = self.runtime_activations.iter().find(|record| {
                record.id == preemption.activation
                    && record.generation == preemption.activation_generation_after
            }) else {
                if self.runtime_activations.iter().any(|record| {
                    record.id == preemption.activation
                        && record.generation > preemption.activation_generation_after
                }) {
                    continue;
                }
                return Err(SemanticInvariantError::PreemptionMissingActivation {
                    preemption: preemption.id,
                    activation: preemption.activation,
                });
            };
            if activation.state == RuntimeActivationState::Runnable {
                let Some(queue) = self.runnable_queues.iter().find(|record| {
                    record.id == preemption.queue
                        && record.generation == preemption.queue_generation
                }) else {
                    return Err(SemanticInvariantError::PreemptionMissingQueue {
                        preemption: preemption.id,
                        queue: preemption.queue,
                    });
                };
                if !queue.entries.iter().any(|entry| {
                    entry.activation == preemption.activation
                        && entry.activation_generation == preemption.activation_generation_after
                }) {
                    return Err(SemanticInvariantError::PreemptionQueueEntryMismatch {
                        preemption: preemption.id,
                        activation: preemption.activation,
                    });
                }
            }
        }

        for decision in &self.scheduler_decisions {
            if decision.state == SchedulerDecisionState::Dropped {
                continue;
            }
            let Some(queue) = self.runnable_queues.iter().find(|record| {
                record.id == decision.queue && record.generation == decision.queue_generation
            }) else {
                return Err(SemanticInvariantError::SchedulerDecisionMissingQueue {
                    decision: decision.id,
                    queue: decision.queue,
                });
            };
            if !self.tasks.iter().any(|task| {
                task.id == decision.owner_task && task.generation == decision.owner_task_generation
            }) {
                return Err(SemanticInvariantError::SchedulerDecisionMissingTask {
                    decision: decision.id,
                    task: decision.owner_task,
                });
            }
            let was_queued_at_decision_generation = self.event_log.events.iter().any(|event| {
                matches!(
                    &event.kind,
                    EventKind::RunnableQueued {
                        queue,
                        activation,
                        activation_generation,
                    } if *queue == decision.queue
                        && *activation == decision.selected_activation
                        && *activation_generation == decision.selected_activation_generation
                )
            });
            if !was_queued_at_decision_generation {
                return Err(
                    SemanticInvariantError::SchedulerDecisionQueueEntryMismatch {
                        decision: decision.id,
                        activation: decision.selected_activation,
                    },
                );
            }
            let Some(activation) = self
                .runtime_activations
                .iter()
                .find(|record| record.id == decision.selected_activation)
            else {
                return Err(SemanticInvariantError::SchedulerDecisionMissingActivation {
                    decision: decision.id,
                    activation: decision.selected_activation,
                });
            };
            if activation.generation < decision.selected_activation_generation {
                return Err(SemanticInvariantError::SchedulerDecisionMissingActivation {
                    decision: decision.id,
                    activation: decision.selected_activation,
                });
            }
            if activation.generation == decision.selected_activation_generation
                && (activation.state != RuntimeActivationState::Runnable
                    || activation.runnable_queue != Some(decision.queue)
                    || activation.runnable_queue_generation != Some(decision.queue_generation))
            {
                return Err(SemanticInvariantError::SchedulerDecisionMissingActivation {
                    decision: decision.id,
                    activation: decision.selected_activation,
                });
            }
            if activation.generation == decision.selected_activation_generation
                && (queue.state != RunnableQueueState::Active
                    || !queue.entries.iter().any(|entry| {
                        entry.activation == decision.selected_activation
                            && entry.activation_generation
                                == decision.selected_activation_generation
                    }))
            {
                return Err(
                    SemanticInvariantError::SchedulerDecisionQueueEntryMismatch {
                        decision: decision.id,
                        activation: decision.selected_activation,
                    },
                );
            }
        }

        Ok(())
    }
}
