use super::*;

impl SemanticGraph {
    pub fn record_wait_created(
        &mut self,
        wait: WaitId,
        owner_task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    ) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
        } else {
            self.waits.push(WaitRecord {
                id: wait,
                owner_task,
                kind,
                generation,
                state: WaitState::Pending,
            });
        }
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            task.pending_wait = Some(wait);
        }
        self.set_task_state(owner_task, TaskState::Pending);
        self.event_log.push(
            "wait",
            EventKind::WaitCreated {
                wait,
                task: owner_task,
                kind,
                generation,
            },
        );
    }
    pub fn record_wait_resolved(&mut self, wait: WaitId, reason: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Ready;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }
    pub fn record_wait_cancelled(&mut self, wait: WaitId, errno: i32) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
        }
        self.event_log
            .push("wait", EventKind::WaitCancelled { wait, errno });
    }
    pub fn record_wait_restarted(&mut self, wait: WaitId, class: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Restarted;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitRestarted {
                wait,
                class: class.to_string(),
            },
        );
    }
    pub fn wait_handle(&self, id: WaitId) -> Option<WaitHandle> {
        self.waits
            .iter()
            .find(|wait| wait.id == id)
            .map(|wait| WaitHandle::new(wait.id, wait.generation))
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
