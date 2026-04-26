use super::*;

impl SemanticGraph {
    pub fn record_wait_created(
        &mut self,
        wait: WaitId,
        owner_task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    ) {
        self.record_wait_created_with_details(
            wait,
            Some(owner_task),
            None,
            None,
            kind,
            generation,
            Vec::new(),
            None,
            RestartPolicy::RestartIfAllowed,
            None,
        );
    }

    pub fn record_wait_created_with_details(
        &mut self,
        wait: WaitId,
        owner_task: Option<TaskId>,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        kind: SemanticWaitKind,
        generation: Generation,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        saved_context: Option<String>,
    ) {
        let owner_task_generation = if let Some(owner_task) = owner_task {
            if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
                task.pending_wait = Some(wait);
            }
            self.set_task_state(owner_task, TaskState::Pending);
            self.tasks
                .iter()
                .find(|task| task.id == owner_task)
                .map(|task| task.generation)
        } else {
            None
        };
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
            record.owner_task = owner_task;
            record.owner_task_generation = owner_task_generation;
            record.owner_store = owner_store;
            record.owner_store_generation = owner_store_generation;
            record.blockers = blockers;
            record.deadline = deadline;
            record.cancel_reason = None;
            record.restart_policy = restart_policy;
            record.saved_context = saved_context;
        } else {
            self.waits.push(WaitRecord {
                id: wait,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                kind,
                generation,
                state: WaitState::Pending,
                blockers,
                deadline,
                cancel_reason: None,
                restart_policy,
                saved_context,
            });
        }
        self.event_log.push(
            "wait",
            EventKind::WaitCreated {
                wait,
                task: owner_task.unwrap_or(0),
                kind,
                generation,
            },
        );
        self.event_log
            .push("wait", EventKind::WaitPending { wait, generation });
    }

    pub fn record_wait_resolved(&mut self, wait: WaitId, reason: &str) {
        let owner_task = self
            .waits
            .iter()
            .find(|record| record.id == wait)
            .and_then(|record| record.owner_task);
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Resolved;
        }
        self.clear_task_wait_if_current(owner_task, wait);
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }

    pub fn record_wait_consumed(&mut self, wait: WaitId) {
        let owner_task = self
            .waits
            .iter()
            .find(|record| record.id == wait)
            .and_then(|record| record.owner_task);
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Consumed;
        }
        self.clear_task_wait_if_current(owner_task, wait);
        self.event_log
            .push("wait", EventKind::WaitConsumed { wait });
    }

    pub fn record_wait_cancelled(&mut self, wait: WaitId, errno: i32) {
        self.record_wait_cancelled_with_reason(wait, errno, WaitCancelReason::ResourceDropped);
    }

    pub fn record_wait_cancelled_with_reason(
        &mut self,
        wait: WaitId,
        errno: i32,
        reason: WaitCancelReason,
    ) {
        let owner_task = self
            .waits
            .iter()
            .find(|record| record.id == wait)
            .and_then(|record| record.owner_task);
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
            record.cancel_reason = Some(reason);
        }
        self.clear_task_wait_if_current(owner_task, wait);
        self.event_log.push(
            "wait",
            EventKind::WaitCancelled {
                wait,
                errno,
                reason,
            },
        );
    }

    pub fn record_wait_interrupted(&mut self, wait: WaitId, reason: WaitCancelReason) {
        let owner_task = self
            .waits
            .iter()
            .find(|record| record.id == wait)
            .and_then(|record| record.owner_task);
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Interrupted;
            record.cancel_reason = Some(reason);
        }
        self.clear_task_wait_if_current(owner_task, wait);
        self.event_log
            .push("wait", EventKind::WaitInterrupted { wait, reason });
    }

    pub fn record_wait_restarted(&mut self, wait: WaitId, class: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Restarted;
            record.generation += 1;
            record.cancel_reason = None;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitRestarted {
                wait,
                class: class.to_string(),
            },
        );
    }

    pub fn wait_index(&self) -> WaitIndex {
        let mut index = WaitIndex::default();
        for wait in &self.waits {
            if let Some(task) = wait.owner_task {
                index
                    .by_task
                    .push((task, wait.owner_task_generation.unwrap_or(0), wait.id));
            }
            if let Some(store) = wait.owner_store {
                index
                    .by_store
                    .push((store, wait.owner_store_generation.unwrap_or(0), wait.id));
            }
            if let Some(deadline) = wait.deadline {
                index.by_deadline.push((deadline, wait.id));
            }
            for blocker in &wait.blockers {
                index.by_resource.push((*blocker, wait.id));
            }
        }
        index
    }

    pub fn fake_timer_event_resolve_wait(&mut self, wait: WaitId, deadline: u64) -> bool {
        let Some(record) = self.waits.iter().find(|record| record.id == wait) else {
            return false;
        };
        if record.deadline != Some(deadline) || record.state != WaitState::Pending {
            return false;
        }
        self.record_wait_resolved(wait, "timer-event");
        true
    }

    pub fn fake_capability_revoke_cancel_wait(&mut self, cap: CapabilityId) -> usize {
        let target = ContractObjectRef::new(ContractObjectKind::Capability, cap, 1);
        let waits = self
            .waits
            .iter()
            .filter(|wait| wait.state == WaitState::Pending && wait.blockers.contains(&target))
            .map(|wait| wait.id)
            .collect::<Vec<_>>();
        for wait in &waits {
            self.record_wait_cancelled_with_reason(*wait, 125, WaitCancelReason::CapabilityRevoked);
        }
        waits.len()
    }

    pub fn block_activation_on_wait_with_id(
        &mut self,
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        activation_generation: Generation,
        wait: WaitId,
        kind: SemanticWaitKind,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        note: &str,
    ) -> bool {
        if activation_wait == 0
            || wait == 0
            || blockers.is_empty() && deadline.is_none()
            || self
                .activation_waits
                .iter()
                .any(|record| record.id == activation_wait)
            || self.waits.iter().any(|record| record.id == wait)
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
        if !self.tasks.iter().any(|task| {
            task.id == owner_task
                && task.generation == owner_task_generation
                && matches!(task.state, TaskState::Runnable | TaskState::Running)
        }) {
            return false;
        }
        let owner_store = self.runtime_activations[activation_index].owner_store;
        let owner_store_generation =
            self.runtime_activations[activation_index].owner_store_generation;
        if let Some(store) = owner_store {
            let Some(generation) = owner_store_generation else {
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

        self.next_activation_wait_id = self.next_activation_wait_id.max(activation_wait + 1);
        self.record_wait_created_with_details(
            wait,
            Some(owner_task),
            owner_store,
            owner_store_generation,
            kind,
            1,
            blockers,
            deadline,
            restart_policy,
            None,
        );
        let Some(wait_record) = self.waits.iter().find(|record| {
            record.id == wait && record.generation == 1 && record.state == WaitState::Pending
        }) else {
            return false;
        };
        let Some(wait_owner_task_generation) = wait_record.owner_task_generation else {
            return false;
        };

        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Pending;
        self.runtime_activations[activation_index].generation += 1;
        self.runtime_activations[activation_index].owner_task_generation =
            wait_owner_task_generation;
        let activation_generation_after = self.runtime_activations[activation_index].generation;
        for context in &mut self.activation_contexts {
            if context.activation == activation && context.state == ActivationContextState::Current
            {
                context.generation += 1;
                context.activation_generation = activation_generation_after;
                context.owner_task_generation = wait_owner_task_generation;
            }
        }
        let state_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Pending,
                generation: activation_generation_after,
            },
        );
        let blocked_event = self.event_log.push(
            "wait",
            EventKind::RuntimeActivationWaitBlocked {
                activation_wait,
                activation,
                from_generation: activation_generation,
                to_generation: activation_generation_after,
                wait,
                wait_generation: 1,
                generation: 1,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(state_event.max(blocked_event));
        self.activation_waits.push(ActivationWaitRecord {
            id: activation_wait,
            activation,
            activation_generation_before: activation_generation,
            activation_generation_after_block: activation_generation_after,
            activation_generation_after_cancel: None,
            wait,
            wait_generation: 1,
            owner_task,
            owner_task_generation: wait_owner_task_generation,
            queue: None,
            queue_generation: None,
            generation: 1,
            state: ActivationWaitState::Pending,
            blocked_at_event: blocked_event,
            completed_at_event: None,
            cancel_reason: None,
            note: note.to_string(),
        });
        true
    }

    pub fn cancel_activation_wait(
        &mut self,
        activation_wait: ActivationWaitId,
        activation_wait_generation: Generation,
        wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: &str,
    ) -> bool {
        let Some(activation_wait_index) = self.activation_waits.iter().position(|record| {
            record.id == activation_wait
                && record.generation == activation_wait_generation
                && record.wait_generation == wait_generation
                && record.state == ActivationWaitState::Pending
        }) else {
            return false;
        };
        let activation = self.activation_waits[activation_wait_index].activation;
        let wait = self.activation_waits[activation_wait_index].wait;
        let activation_generation =
            self.activation_waits[activation_wait_index].activation_generation_after_block;
        if !self.waits.iter().any(|record| {
            record.id == wait
                && record.generation == wait_generation
                && record.state == WaitState::Pending
        }) {
            return false;
        }
        let Some(activation_index) = self.runtime_activations.iter().position(|record| {
            record.id == activation
                && record.generation == activation_generation
                && record.state == RuntimeActivationState::Pending
                && record.runnable_queue.is_none()
                && record.runnable_queue_generation.is_none()
        }) else {
            return false;
        };

        self.record_wait_cancelled_with_reason(wait, errno, reason);
        let owner_task = self.activation_waits[activation_wait_index].owner_task;
        let Some(owner_task_generation) = self
            .tasks
            .iter()
            .find(|task| task.id == owner_task)
            .map(|task| task.generation)
        else {
            return false;
        };
        let from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Blocked;
        self.runtime_activations[activation_index].generation += 1;
        self.runtime_activations[activation_index].owner_task_generation = owner_task_generation;
        let activation_generation_after = self.runtime_activations[activation_index].generation;
        for context in &mut self.activation_contexts {
            if context.activation == activation && context.state == ActivationContextState::Current
            {
                context.generation += 1;
                context.activation_generation = activation_generation_after;
                context.owner_task_generation = owner_task_generation;
            }
        }
        let state_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from,
                to: RuntimeActivationState::Blocked,
                generation: activation_generation_after,
            },
        );
        let cancelled_event = self.event_log.push(
            "wait",
            EventKind::RuntimeActivationWaitCancelled {
                activation_wait,
                activation,
                from_generation: activation_generation,
                to_generation: activation_generation_after,
                wait,
                wait_generation,
                reason,
                generation: activation_wait_generation,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(state_event.max(cancelled_event));
        self.activation_waits[activation_wait_index].state = ActivationWaitState::Cancelled;
        self.activation_waits[activation_wait_index].activation_generation_after_cancel =
            Some(activation_generation_after);
        self.activation_waits[activation_wait_index].completed_at_event = Some(cancelled_event);
        self.activation_waits[activation_wait_index].cancel_reason = Some(reason);
        self.activation_waits[activation_wait_index].note = note.to_string();
        true
    }

    fn clear_task_wait_if_current(&mut self, owner_task: Option<TaskId>, wait: WaitId) {
        let Some(owner_task) = owner_task else {
            return;
        };
        let should_clear = self
            .tasks
            .iter()
            .any(|task| task.id == owner_task && task.pending_wait == Some(wait));
        if !should_clear {
            return;
        }
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            task.pending_wait = None;
        }
        self.set_task_state(owner_task, TaskState::Runnable);
    }

    pub fn wait_handle(&self, id: WaitId) -> Option<WaitHandle> {
        self.waits
            .iter()
            .find(|wait| wait.id == id)
            .map(|wait| WaitHandle::new(wait.id, wait.generation))
    }

    pub fn wait_records(&self) -> &[WaitRecord] {
        &self.waits
    }

    pub fn activation_waits(&self) -> &[ActivationWaitRecord] {
        &self.activation_waits
    }

    pub fn validate_wait_handle(&mut self, handle: WaitHandle) -> Result<(), GenerationCheckError> {
        let wait = self.waits.iter().find(|wait| wait.id == handle.id);
        let actual = wait.map(|wait| wait.generation);
        let result = match wait {
            None => Err(GenerationCheckError::Missing),
            Some(wait) if wait.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenValidated {
                        wait: handle.id,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenRejected {
                        wait: handle.id,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }
    pub fn wait_count(&self) -> usize {
        self.waits.len()
    }
    pub fn pending_wait_count(&self) -> usize {
        self.waits
            .iter()
            .filter(|wait| wait.state == WaitState::Pending)
            .count()
    }

    pub fn activation_wait_count(&self) -> usize {
        self.activation_waits.len()
    }

    pub fn check_wait_invariants(&self) -> Result<(), SemanticInvariantError> {
        for wait in &self.waits {
            if wait.state == WaitState::Pending {
                if wait.owner_task.is_none() && wait.owner_store.is_none() {
                    return Err(SemanticInvariantError::WaitReferencesMissingTask {
                        wait: wait.id,
                        task: 0,
                    });
                }
                if wait.blockers.is_empty() && wait.deadline.is_none() {
                    return Err(SemanticInvariantError::WaitMissingBlocker { wait: wait.id });
                }
                if let Some(owner_task) = wait.owner_task {
                    let Some(owner_task_generation) = wait.owner_task_generation else {
                        return Err(SemanticInvariantError::WaitReferencesMissingTask {
                            wait: wait.id,
                            task: owner_task,
                        });
                    };
                    let Some(task) = self.tasks.iter().find(|task| {
                        task.id == owner_task && task.generation == owner_task_generation
                    }) else {
                        return Err(SemanticInvariantError::WaitReferencesMissingTask {
                            wait: wait.id,
                            task: owner_task,
                        });
                    };
                    if task.state != TaskState::Pending || task.pending_wait != Some(wait.id) {
                        return Err(SemanticInvariantError::WaitReferencesMissingTask {
                            wait: wait.id,
                            task: owner_task,
                        });
                    }
                }
                if let Some(owner_store) = wait.owner_store {
                    let Some(owner_store_generation) = wait.owner_store_generation else {
                        return Err(SemanticInvariantError::WaitReferencesMissingStore {
                            wait: wait.id,
                            store: owner_store,
                        });
                    };
                    if !self.stores.iter().any(|store| {
                        store.id == owner_store
                            && store.generation == owner_store_generation
                            && store.state != StoreState::Dead
                    }) {
                        return Err(SemanticInvariantError::WaitReferencesMissingStore {
                            wait: wait.id,
                            store: owner_store,
                        });
                    }
                }
            }
        }

        for activation_wait in &self.activation_waits {
            if activation_wait.state == ActivationWaitState::Dropped {
                continue;
            }
            let Some(wait) = self.waits.iter().find(|wait| {
                wait.id == activation_wait.wait
                    && wait.generation == activation_wait.wait_generation
            }) else {
                return Err(SemanticInvariantError::ActivationWaitMissingWait {
                    activation_wait: activation_wait.id,
                    wait: activation_wait.wait,
                });
            };
            let Some(task) = self
                .tasks
                .iter()
                .find(|task| task.id == activation_wait.owner_task)
            else {
                return Err(SemanticInvariantError::ActivationWaitMissingTask {
                    activation_wait: activation_wait.id,
                    task: activation_wait.owner_task,
                });
            };
            if task.generation < activation_wait.owner_task_generation {
                return Err(SemanticInvariantError::ActivationWaitMissingTask {
                    activation_wait: activation_wait.id,
                    task: activation_wait.owner_task,
                });
            }
            let Some(activation) = self
                .runtime_activations
                .iter()
                .find(|activation| activation.id == activation_wait.activation)
            else {
                return Err(SemanticInvariantError::ActivationWaitMissingActivation {
                    activation_wait: activation_wait.id,
                    activation: activation_wait.activation,
                });
            };
            match activation_wait.state {
                ActivationWaitState::Pending => {
                    if wait.state != WaitState::Pending {
                        return Err(SemanticInvariantError::ActivationWaitMissingWait {
                            activation_wait: activation_wait.id,
                            wait: activation_wait.wait,
                        });
                    }
                    if task.generation != activation_wait.owner_task_generation
                        || task.state != TaskState::Pending
                        || task.pending_wait != Some(activation_wait.wait)
                    {
                        return Err(SemanticInvariantError::ActivationWaitMissingTask {
                            activation_wait: activation_wait.id,
                            task: activation_wait.owner_task,
                        });
                    }
                    if activation.generation != activation_wait.activation_generation_after_block
                        || activation.state != RuntimeActivationState::Pending
                        || activation.runnable_queue.is_some()
                        || activation.runnable_queue_generation.is_some()
                    {
                        return Err(SemanticInvariantError::ActivationWaitMissingActivation {
                            activation_wait: activation_wait.id,
                            activation: activation_wait.activation,
                        });
                    }
                }
                ActivationWaitState::Cancelled | ActivationWaitState::Resolved => {
                    if activation.generation
                        < activation_wait
                            .activation_generation_after_cancel
                            .unwrap_or(activation_wait.activation_generation_after_block)
                    {
                        return Err(SemanticInvariantError::ActivationWaitMissingActivation {
                            activation_wait: activation_wait.id,
                            activation: activation_wait.activation,
                        });
                    }
                    if activation.state == RuntimeActivationState::Runnable {
                        return Err(SemanticInvariantError::ActivationWaitRunnableLeak {
                            activation_wait: activation_wait.id,
                            activation: activation_wait.activation,
                        });
                    }
                }
                ActivationWaitState::Dropped => {}
            }
        }

        Ok(())
    }
}
