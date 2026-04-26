use super::*;

impl SemanticGraph {
    pub fn cleanup_activation_for_store_fault_with_id(
        &mut self,
        cleanup: ActivationCleanupId,
        store: StoreId,
        store_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        wait: Option<WaitId>,
        wait_generation: Option<Generation>,
        reason: &str,
        note: &str,
    ) -> bool {
        if cleanup == 0
            || self
                .activation_cleanups
                .iter()
                .any(|record| record.id == cleanup)
            || reason.is_empty()
        {
            return false;
        }
        let Some(store_index) = self.stores.iter().position(|record| {
            record.id == store
                && record.generation == store_generation
                && record.state != StoreState::Dead
        }) else {
            return false;
        };
        let Some(activation_index) = self.runtime_activations.iter().position(|record| {
            record.id == activation
                && record.generation == activation_generation
                && record.owner_store == Some(store)
                && record.owner_store_generation == Some(store_generation)
                && !matches!(
                    record.state,
                    RuntimeActivationState::Dead | RuntimeActivationState::Exited
                )
        }) else {
            return false;
        };
        match (wait, wait_generation) {
            (Some(wait), Some(generation)) => {
                if !self.waits.iter().any(|record| {
                    record.id == wait
                        && record.generation == generation
                        && record.state == WaitState::Pending
                        && record.owner_store == Some(store)
                        && record.owner_store_generation == Some(store_generation)
                }) {
                    return false;
                }
            }
            (Some(_), None) | (None, Some(_)) => return false,
            (None, None) => {}
        }

        self.next_activation_cleanup_id = self.next_activation_cleanup_id.max(cleanup + 1);
        let owner_task = self.runtime_activations[activation_index].owner_task;
        let owner_task_generation_before =
            self.runtime_activations[activation_index].owner_task_generation;
        let started_at_event = self.event_log.push(
            "cleanup",
            EventKind::RuntimeActivationCleanupStarted {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                generation: 1,
            },
        );
        let mut steps = Vec::new();

        let activation_ref = ContractObjectRef::new(
            ContractObjectKind::Activation,
            activation,
            activation_generation,
        );
        let stopped_new_activation = self.remove_activation_from_runnable_queues(activation);
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::StopNewActivation,
            target: activation_ref,
            observed_generation: activation_generation,
            status: if stopped_new_activation {
                ActivationCleanupStepStatus::Done
            } else {
                ActivationCleanupStepStatus::SkippedNotPresent
            },
            event: Some(started_at_event),
        });

        let mut cancelled_wait = None;
        if let (Some(wait), Some(wait_generation)) = (wait, wait_generation) {
            let Some(wait_index) = self.waits.iter().position(|record| {
                record.id == wait
                    && record.generation == wait_generation
                    && record.state == WaitState::Pending
            }) else {
                return false;
            };
            self.waits[wait_index].state = WaitState::Cancelled;
            self.waits[wait_index].cancel_reason = Some(WaitCancelReason::StoreFault);
            let wait_event = self.event_log.push(
                "wait",
                EventKind::WaitCancelled {
                    wait,
                    errno: 5,
                    reason: WaitCancelReason::StoreFault,
                },
            );
            steps.push(ActivationCleanupStepRecord {
                kind: ActivationCleanupStepKind::CancelWait,
                target: ContractObjectRef::new(
                    ContractObjectKind::WaitToken,
                    wait,
                    wait_generation,
                ),
                observed_generation: wait_generation,
                status: ActivationCleanupStepStatus::Done,
                event: Some(wait_event),
            });
            cancelled_wait = Some((wait, wait_generation, wait_event));
        } else {
            steps.push(ActivationCleanupStepRecord {
                kind: ActivationCleanupStepKind::CancelWait,
                target: activation_ref,
                observed_generation: activation_generation,
                status: ActivationCleanupStepStatus::SkippedNotPresent,
                event: Some(started_at_event),
            });
        }

        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            if let Some((wait, _, _)) = cancelled_wait
                && task.pending_wait == Some(wait)
            {
                task.pending_wait = None;
            }
        }
        self.set_task_state(owner_task, TaskState::Faulted);
        let owner_task_generation_after = self
            .tasks
            .iter()
            .find(|task| task.id == owner_task)
            .map(|task| task.generation)
            .unwrap_or(owner_task_generation_before);
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::MarkTaskFaulted,
            target: ContractObjectRef::new(
                ContractObjectKind::Task,
                u64::from(owner_task),
                owner_task_generation_before,
            ),
            observed_generation: owner_task_generation_before,
            status: ActivationCleanupStepStatus::Done,
            event: Some(self.event_log.cursor()),
        });

        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Dead;
        self.runtime_activations[activation_index].generation += 1;
        self.runtime_activations[activation_index].runnable_queue = None;
        self.runtime_activations[activation_index].runnable_queue_generation = None;
        self.runtime_activations[activation_index].owner_task_generation =
            owner_task_generation_after;
        let activation_generation_after = self.runtime_activations[activation_index].generation;
        let activation_dead_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Dead,
                generation: activation_generation_after,
            },
        );
        self.runtime_activations[activation_index].last_event = Some(activation_dead_event);
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::SealActivation,
            target: activation_ref,
            observed_generation: activation_generation,
            status: ActivationCleanupStepStatus::Done,
            event: Some(activation_dead_event),
        });

        if let Some((wait, wait_generation, wait_event)) = cancelled_wait {
            if let Some(activation_wait_index) = self.activation_waits.iter().position(|record| {
                record.activation == activation
                    && record.activation_generation_after_block == activation_generation
                    && record.wait == wait
                    && record.wait_generation == wait_generation
                    && record.state == ActivationWaitState::Pending
            }) {
                self.activation_waits[activation_wait_index].state = ActivationWaitState::Cancelled;
                self.activation_waits[activation_wait_index].activation_generation_after_cancel =
                    Some(activation_generation_after);
                self.activation_waits[activation_wait_index].completed_at_event = Some(wait_event);
                self.activation_waits[activation_wait_index].cancel_reason =
                    Some(WaitCancelReason::StoreFault);
                let _ = self.event_log.push(
                    "wait",
                    EventKind::RuntimeActivationWaitCancelled {
                        activation_wait: self.activation_waits[activation_wait_index].id,
                        activation,
                        from_generation: activation_generation,
                        to_generation: activation_generation_after,
                        wait,
                        wait_generation,
                        reason: WaitCancelReason::StoreFault,
                        generation: self.activation_waits[activation_wait_index].generation,
                    },
                );
            }
        }

        let mut dropped_context = false;
        for context in &mut self.activation_contexts {
            if context.activation == activation && context.state != ActivationContextState::Dropped
            {
                context.generation += 1;
                context.activation_generation = activation_generation_after;
                context.owner_task_generation = owner_task_generation_after;
                context.state = ActivationContextState::Dropped;
                context.current_saved_context = None;
                context.current_saved_context_generation = None;
                context.last_event = Some(activation_dead_event);
                dropped_context = true;
            }
        }
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::DropContext,
            target: activation_ref,
            observed_generation: activation_generation_after,
            status: if dropped_context {
                ActivationCleanupStepStatus::Done
            } else {
                ActivationCleanupStepStatus::SkippedNotPresent
            },
            event: Some(activation_dead_event),
        });

        let resource_cleanup = self.cleanup_resources_owned_by_store(store);
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::DropResources,
            target: ContractObjectRef::new(ContractObjectKind::Store, store, store_generation),
            observed_generation: store_generation,
            status: if resource_cleanup.closed_resources == 0 {
                ActivationCleanupStepStatus::SkippedNotPresent
            } else {
                ActivationCleanupStepStatus::Done
            },
            event: Some(self.event_log.cursor()),
        });

        self.set_store_state(store, StoreState::Cleaning);
        self.set_store_state(store, StoreState::Dead);
        let result_store_generation = self.stores[store_index].generation;
        self.runtime_activations[activation_index].owner_store_generation =
            Some(result_store_generation);
        for context in &mut self.activation_contexts {
            if context.activation == activation {
                context.owner_store_generation = Some(result_store_generation);
            }
        }
        steps.push(ActivationCleanupStepRecord {
            kind: ActivationCleanupStepKind::MarkStoreDead,
            target: ContractObjectRef::new(ContractObjectKind::Store, store, store_generation),
            observed_generation: store_generation,
            status: ActivationCleanupStepStatus::Done,
            event: Some(self.event_log.cursor()),
        });

        let completed_at_event = self.event_log.push(
            "cleanup",
            EventKind::RuntimeActivationCleanupCompleted {
                cleanup,
                store,
                target_store_generation: store_generation,
                result_store_generation,
                activation,
                activation_generation_before: activation_generation,
                activation_generation_after,
                generation: 1,
            },
        );
        self.activation_cleanups.push(ActivationCleanupRecord {
            id: cleanup,
            store,
            target_store_generation: store_generation,
            result_store_generation,
            activation,
            activation_generation_before: activation_generation,
            activation_generation_after,
            wait,
            wait_generation,
            owner_task,
            owner_task_generation_before,
            owner_task_generation_after,
            generation: 1,
            state: ActivationCleanupState::Completed,
            reason: reason.to_string(),
            started_at_event,
            completed_at_event,
            steps,
            note: note.to_string(),
        });
        true
    }

    fn remove_activation_from_runnable_queues(&mut self, activation: ActivationId) -> bool {
        let mut removed = false;
        for queue in &mut self.runnable_queues {
            let before = queue.entries.len();
            queue.entries.retain(|entry| entry.activation != activation);
            removed |= queue.entries.len() != before;
        }
        removed
    }

    pub fn activation_cleanups(&self) -> &[ActivationCleanupRecord] {
        &self.activation_cleanups
    }

    pub fn activation_cleanup_count(&self) -> usize {
        self.activation_cleanups.len()
    }

    pub fn check_cleanup_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cleanup in &self.activation_cleanups {
            let Some(store) = self.stores.iter().find(|store| store.id == cleanup.store) else {
                return Err(SemanticInvariantError::ActivationCleanupMissingStore {
                    cleanup: cleanup.id,
                    store: cleanup.store,
                });
            };
            if cleanup.state == ActivationCleanupState::Completed
                && (store.generation < cleanup.result_store_generation
                    || (store.generation == cleanup.result_store_generation
                        && store.state != StoreState::Dead))
            {
                return Err(SemanticInvariantError::ActivationCleanupMissingStore {
                    cleanup: cleanup.id,
                    store: cleanup.store,
                });
            }
            let Some(activation) = self
                .runtime_activations
                .iter()
                .find(|record| record.id == cleanup.activation)
            else {
                return Err(SemanticInvariantError::ActivationCleanupMissingActivation {
                    cleanup: cleanup.id,
                    activation: cleanup.activation,
                });
            };
            if cleanup.state == ActivationCleanupState::Completed
                && (activation.generation != cleanup.activation_generation_after
                    || activation.state != RuntimeActivationState::Dead
                    || activation.owner_store != Some(cleanup.store)
                    || activation
                        .owner_store_generation
                        .is_none_or(|generation| generation < cleanup.result_store_generation))
            {
                return Err(SemanticInvariantError::ActivationCleanupMissingActivation {
                    cleanup: cleanup.id,
                    activation: cleanup.activation,
                });
            }
            if let (Some(wait), Some(wait_generation)) = (cleanup.wait, cleanup.wait_generation) {
                let Some(wait_record) = self
                    .waits
                    .iter()
                    .find(|record| record.id == wait && record.generation == wait_generation)
                else {
                    return Err(SemanticInvariantError::ActivationCleanupMissingWait {
                        cleanup: cleanup.id,
                        wait,
                    });
                };
                if cleanup.state == ActivationCleanupState::Completed
                    && (wait_record.state != WaitState::Cancelled
                        || wait_record.cancel_reason != Some(WaitCancelReason::StoreFault))
                {
                    return Err(SemanticInvariantError::ActivationCleanupMissingWait {
                        cleanup: cleanup.id,
                        wait,
                    });
                }
            }
            let Some(task) = self.tasks.iter().find(|task| task.id == cleanup.owner_task) else {
                return Err(SemanticInvariantError::ActivationCleanupMissingTask {
                    cleanup: cleanup.id,
                    task: cleanup.owner_task,
                });
            };
            if cleanup.state == ActivationCleanupState::Completed
                && (task.generation != cleanup.owner_task_generation_after
                    || task.state != TaskState::Faulted
                    || task.pending_wait.is_some())
            {
                return Err(SemanticInvariantError::ActivationCleanupMissingTask {
                    cleanup: cleanup.id,
                    task: cleanup.owner_task,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_activation_cleanup_after_generation_for_test(
        &mut self,
        cleanup: ActivationCleanupId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .activation_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup)
        {
            record.activation_generation_after = generation;
        }
    }
}
