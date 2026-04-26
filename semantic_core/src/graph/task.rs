use super::*;

impl SemanticGraph {
    pub fn ensure_task(&mut self, id: TaskId, frontend: FrontendKind, label: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.frontend = frontend;
            task.label = label.to_string();
            return;
        }

        self.tasks.push(TaskRecord {
            id,
            label: label.to_string(),
            frontend,
            state: TaskState::Runnable,
            fault_domain: None,
            pending_wait: None,
            generation: 1,
            resources: Vec::new(),
        });
        self.event_log
            .push("semantic", EventKind::TaskCreated { task: id, frontend });
    }
    pub fn set_task_state(&mut self, id: TaskId, state: TaskState) {
        let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) else {
            return;
        };
        let from = task.state;
        if from == state {
            return;
        }
        task.state = state;
        task.generation += 1;
        if state != TaskState::Pending {
            task.pending_wait = None;
        }
        self.event_log.push(
            "scheduler",
            EventKind::TaskStateChanged {
                task: id,
                from,
                to: state,
            },
        );
    }
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn tasks(&self) -> &[TaskRecord] {
        &self.tasks
    }
}
