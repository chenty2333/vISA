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
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
            record.owner_task = owner_task;
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
        if let Some(owner_task) = owner_task {
            if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
                task.pending_wait = Some(wait);
            }
            self.set_task_state(owner_task, TaskState::Pending);
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
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Resolved;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }

    pub fn record_wait_consumed(&mut self, wait: WaitId) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Consumed;
        }
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
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
            record.cancel_reason = Some(reason);
        }
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
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Interrupted;
            record.cancel_reason = Some(reason);
        }
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
                index.by_task.push((task, wait.id));
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
    pub fn wait_handle(&self, id: WaitId) -> Option<WaitHandle> {
        self.waits
            .iter()
            .find(|wait| wait.id == id)
            .map(|wait| WaitHandle::new(wait.id, wait.generation))
    }

    pub fn wait_records(&self) -> &[WaitRecord] {
        &self.waits
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
}
