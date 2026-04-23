use super::events::{Event, EventQueue};
use super::types::TaskId;

const BOOTSTRAP_TASK_ID: TaskId = 1;

pub(crate) struct Scheduler {
    current_task: TaskId,
    next_task: TaskId,
    events: EventQueue,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            current_task: BOOTSTRAP_TASK_ID,
            next_task: BOOTSTRAP_TASK_ID + 1,
            events: EventQueue::new(),
        }
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        BOOTSTRAP_TASK_ID
    }

    pub(crate) fn current_task(&self) -> TaskId {
        self.current_task
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.current_task = task;
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        let task = self.next_task;
        self.next_task += 1;
        task
    }

    pub(crate) fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub(crate) fn pop_event(&mut self) -> Option<Event> {
        self.events.pop()
    }
}
